package me.bmax.apatch.util

import com.topjohnwu.superuser.io.SuFile
import com.topjohnwu.superuser.io.SuFileInputStream

fun isMetaModuleMode(): Boolean {
    val modeFile = SuFile.open("/data/adb/.mount_mode")
    return if (modeFile.exists()) {
        try {
            SuFileInputStream.open(modeFile).use { 
                it.readBytes().toString(Charsets.UTF_8).trim() 
            } == "metamodule"
        } catch (e: Exception) {
            false
        }
    } else {
        false
    }
}
