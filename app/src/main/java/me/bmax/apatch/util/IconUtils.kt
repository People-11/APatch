package me.bmax.apatch.util

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import me.bmax.apatch.BuildConfig

object IconUtils {
    fun switchIcon(context: Context, enableDynamic: Boolean) {
        val packageManager = context.packageManager
        val packageName = BuildConfig.APPLICATION_ID

        val defaultAlias = ComponentName(packageName, "me.bmax.apatch.ui.MainActivityDefault")
        val dynamicAlias = ComponentName(packageName, "me.bmax.apatch.ui.MainActivityDynamic")

        if (enableDynamic) {
            packageManager.setComponentEnabledSetting(
                dynamicAlias,
                PackageManager.COMPONENT_ENABLED_STATE_ENABLED,
                PackageManager.DONT_KILL_APP
            )
            packageManager.setComponentEnabledSetting(
                defaultAlias,
                PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                PackageManager.DONT_KILL_APP
            )
        } else {
            packageManager.setComponentEnabledSetting(
                defaultAlias,
                PackageManager.COMPONENT_ENABLED_STATE_ENABLED,
                PackageManager.DONT_KILL_APP
            )
            packageManager.setComponentEnabledSetting(
                dynamicAlias,
                PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                PackageManager.DONT_KILL_APP
            )
        }
    }
}
