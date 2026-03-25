package me.bmax.apatch

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import me.bmax.apatch.util.PkgConfig
import me.bmax.apatch.util.rootShellForResult
import kotlin.concurrent.thread

class InstallReceiver : BroadcastReceiver() {
    companion object {
        private const val CHANNEL_ID = "apatch_install"
        private const val NOTIFY_BASE = 10000
        const val ACTION_GRANT = "me.bmax.apatch.action.GRANT_ROOT"
        const val ACTION_EXCLUDE = "me.bmax.apatch.action.EXCLUDE_APP"
        const val ACTION_APP_UNINSTALLED = "me.bmax.apatch.ACTION_APP_UNINSTALLED"
    }

    override fun onReceive(context: Context, intent: Intent) {
        val pkg = intent.getStringExtra("pkg") ?: intent.getStringExtra("package_name") ?: return
        when (intent.action) {
            ACTION_GRANT -> handleAction(context, pkg, true)
            ACTION_EXCLUDE -> handleAction(context, pkg, false)
            ACTION_APP_UNINSTALLED -> dismissNotification(context, pkg)
            else -> showNotification(context, pkg)
        }
    }

    private fun handleAction(context: Context, pkg: String, isGrant: Boolean) {
        val uid = try { context.packageManager.getApplicationInfo(pkg, 0).uid } catch (e: Exception) { return }
        thread {
            val sctx = if (isGrant) APApplication.MAGISK_SCONTEXT else APApplication.DEFAULT_SCONTEXT
            val config = PkgConfig.Config(pkg, if (isGrant) 0 else 1, if (isGrant) 1 else 0, Natives.Profile(uid, 0, sctx))
            PkgConfig.changeConfig(config)
            if (isGrant) {
                Natives.grantSu(uid, 0, sctx)
                Natives.setUidExclude(uid, 0)
            } else {
                Natives.revokeSu(uid)
                Natives.setUidExclude(uid, 1)
            }
            thread { rootShellForResult("killall -SIGPWR apd") }
            dismissNotification(context, pkg)
        }
    }

    private fun showNotification(context: Context, pkg: String) {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= 26) {
            nm.createNotificationChannel(NotificationChannel(CHANNEL_ID, "App Install", NotificationManager.IMPORTANCE_HIGH))
        }
        val appName = try { context.packageManager.getApplicationLabel(context.packageManager.getApplicationInfo(pkg, 0)).toString() } catch (e: Exception) { pkg }
        val notify = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle(context.getString(R.string.notification_app_installed_title, appName))
            .setContentText(context.getString(R.string.notification_grant_root_question))
            .setPriority(NotificationCompat.PRIORITY_HIGH).setAutoCancel(true)
            .addAction(0, context.getString(R.string.notification_action_exclude), createPI(context, ACTION_EXCLUDE, pkg))
            .addAction(0, context.getString(R.string.notification_action_grant), createPI(context, ACTION_GRANT, pkg))
            .build()
        NotificationManagerCompat.from(context).notify(NOTIFY_BASE + pkg.hashCode(), notify)
    }

    private fun createPI(context: Context, action: String, pkg: String) = PendingIntent.getBroadcast(
        context, pkg.hashCode() + action.hashCode(),
        Intent(context, InstallReceiver::class.java).apply { this.action = action; putExtra("package_name", pkg) },
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
    )

    private fun dismissNotification(context: Context, pkg: String) =
        NotificationManagerCompat.from(context).cancel(NOTIFY_BASE + pkg.hashCode())
}
