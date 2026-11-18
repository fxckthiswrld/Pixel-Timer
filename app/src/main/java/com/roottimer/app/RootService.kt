package com.roottimer.app

import android.content.Context
import android.os.Process
import java.io.File
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Runs the Pixel 10 Pro XL payload through Shizuku's shell UserService. */
class RootService(private val context: Context) : IRootService.Stub() {

    private val running = AtomicBoolean(false)

    companion object {
        private const val WORK_DIR = "/data/local/tmp/pixel-timer-app"
        private const val ASSET_KSUD = "ksud-pixel"
        private const val WAIT_MINUTES = 8L
    }

    override fun isReady(): Boolean = Process.myUid() == 2000 && DeviceProfile.isSupported()

    override fun isRooted(): Boolean = moduleLive()

    override fun destroy() {}

    private fun moduleLive(): Boolean = try {
        File("/proc/modules").useLines { lines ->
            lines.any { it.startsWith("kernelsu ") }
        }
    } catch (_: Exception) {
        false
    }

    private fun bootId(): String = try {
        File("/proc/sys/kernel/random/boot_id").readText().trim()
    } catch (_: Exception) {
        ""
    }

    /** A park leaves a stale timer node in a live process; only a reboot clears it. */
    private fun isParkedOnThisBoot(): Boolean {
        val prefs = context.getSharedPreferences(Prefs.NAME, Context.MODE_PRIVATE)
        if (!prefs.getBoolean(Prefs.PARKED, false)) return false
        val saved = prefs.getString(Prefs.PARKED_BOOT, "") ?: ""
        val now = bootId()
        if (now.isNotEmpty() && saved.isNotEmpty() && saved != now) {
            prefs.edit().putBoolean(Prefs.PARKED, false).remove(Prefs.PARKED_BOOT).apply()
            return false
        }
        return true
    }

    private fun markParked() {
        context.getSharedPreferences(Prefs.NAME, Context.MODE_PRIVATE).edit()
            .putBoolean(Prefs.PARKED, true)
            .putString(Prefs.PARKED_BOOT, bootId())
            .apply()
    }

    override fun runExploit(callback: IRootCallback?) {
        if (callback == null) return
        if (!running.compareAndSet(false, true)) {
            callback.onLog("error: another run is already in progress")
            callback.onComplete(1, false)
            return
        }
        Thread({
            var code = 1
            try {
                code = runChain(callback)
            } catch (e: Exception) {
                log(callback, "error: ${e.message}")
            } finally {
                runCatching { callback.onComplete(code, code == 0 && moduleLive()) }
                running.set(false)
            }
        }, "pixel-timer-runner").start()
    }

    private fun log(callback: IRootCallback, line: String) {
        runCatching { callback.onLog(line) }
    }

    private fun runChain(callback: IRootCallback): Int {
        if (Process.myUid() != 2000) {
            log(callback, "error: Shizuku shell (uid 2000) is required")
            return 1
        }
        if (!DeviceProfile.isSupported()) {
            log(callback, "error: unsupported device, kernel, or page size; Pixel 10 Pro XL profile only")
            return 2
        }
        if (isParkedOnThisBoot()) {
            log(callback, "error: a previous attempt parked a stale timer holder; reboot before retrying")
            return 6
        }
        if (moduleLive()) {
            log(callback, "KernelSU Next is already loaded")
            return 0
        }

        val timer = File(context.applicationInfo.nativeLibraryDir, "libtimer.so")
        if (!timer.isFile) {
            log(callback, "error: Pixel payload is missing")
            return 1
        }
        val workDir = File(WORK_DIR)
        if (!workDir.isDirectory && !workDir.mkdirs()) {
            log(callback, "error: cannot create $WORK_DIR")
            return 1
        }
        val ksud = File(workDir, "ksud")
        try {
            context.assets.open(ASSET_KSUD).use { input ->
                ksud.outputStream().use { output -> input.copyTo(output) }
            }
            if (!ksud.setReadable(true, true) || !ksud.setExecutable(true, true)) {
                log(callback, "error: cannot set ksud permissions")
                return 1
            }
        } catch (e: Exception) {
            log(callback, "error: cannot stage KernelSU Next: ${e.message}")
            return 1
        }

        log(callback, "Pixel 10 Pro XL profile matched; starting root and KernelSU Next load")
        // Keep the native transcript on disk; the UI log is lost on a park and
        // the free_seen/pipe_hit/stage lines are what decides the next fix.
        val diag = try {
            File(workDir, "last-run.log").bufferedWriter()
        } catch (_: Exception) {
            null
        }
        val proc = ProcessBuilder(timer.absolutePath, "--install")
            .directory(workDir)
            .redirectErrorStream(true)
            .start()
        val parkedNow = AtomicBoolean(false)
        val reader = Thread({
            try {
                proc.inputStream.bufferedReader().useLines { lines ->
                    for (line in lines) {
                        log(callback, line)
                        runCatching {
                            diag?.append(line)
                            diag?.append('\n')
                            diag?.flush()
                        }
                        if (line.contains("parking without reap") &&
                            parkedNow.compareAndSet(false, true)
                        ) {
                            markParked()
                            log(callback, "PARKED: reboot the phone — do not kill Pixel Timer")
                        }
                    }
                }
            } catch (_: Exception) {}
            runCatching { diag?.close() }
        }, "pixel-timer-log")
        reader.isDaemon = true
        reader.start()

        // The payload parks instead of reaping a stale node on a missed reclaim.
        // Detect that marker and return immediately; the process must stay alive
        // until the reboot clears it.
        val deadline = System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(WAIT_MINUTES)
        while (System.currentTimeMillis() < deadline) {
            if (proc.waitFor(1, TimeUnit.SECONDS)) {
                val exit = proc.exitValue()
                reader.join(1000)
                if (exit != 0) {
                    log(callback, "error: Pixel payload exited $exit")
                    return exit
                }
                if (!moduleLive()) {
                    log(callback, "error: payload finished but KernelSU Next is not loaded")
                    return 5
                }
                log(callback, "KSU_LOADED")
                return 0
            }
            if (parkedNow.get()) {
                log(callback, "error: parked stale timer holder; reboot before another attempt")
                return 6
            }
        }
        // The native payload may be holding a reclaimed kernel page.
        // Leave it running; a reboot is the safe recovery path.
        log(callback, "error: timed out; reboot before trying again")
        return 4
    }
}
