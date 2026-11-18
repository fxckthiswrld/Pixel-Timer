package com.roottimer.app

import android.os.Build
import android.system.Os
import android.system.OsConstants

/** Exact profile used to derive the native payload's kernel offsets. */
object DeviceProfile {
    const val DEVICE = "mustang"
    const val KERNEL = "6.6.127-android15-8-g91d825611104-ab16252310-4k"
    const val PAGE_SIZE = 4096L

    fun isSupported(): Boolean = try {
        Build.DEVICE == DEVICE && Os.uname().release == KERNEL &&
            Os.sysconf(OsConstants._SC_PAGESIZE) == PAGE_SIZE
    } catch (_: Exception) {
        false
    }
}
