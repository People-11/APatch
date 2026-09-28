package me.bmax.apatch.util

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager

object IconUtils {
    private const val STATIC_ALIAS = "me.bmax.apatch.ui.MainActivityDefault"
    private const val THEMED_ALIAS = "me.bmax.apatch.ui.MainActivityDynamic"

    /**
     * Swap which launcher alias carries the icon.
     *
     * MainActivity itself has no LAUNCHER filter, so exactly one alias has to
     * stay enabled or the app disappears from the launcher. Enabling comes
     * first for that reason: if the process dies between the two calls, the
     * worst case is two icons rather than none.
     */
    fun switchIcon(context: Context, themed: Boolean) {
        val pm = context.packageManager
        val on = if (themed) THEMED_ALIAS else STATIC_ALIAS
        val off = if (themed) STATIC_ALIAS else THEMED_ALIAS

        pm.setComponentEnabledSetting(
            ComponentName(context, on),
            PackageManager.COMPONENT_ENABLED_STATE_ENABLED,
            PackageManager.DONT_KILL_APP
        )
        pm.setComponentEnabledSetting(
            ComponentName(context, off),
            PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
            PackageManager.DONT_KILL_APP
        )
    }
}
