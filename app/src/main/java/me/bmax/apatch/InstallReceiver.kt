package me.bmax.apatch

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import me.bmax.apatch.util.PkgConfig
import kotlin.concurrent.thread

/**
 * Offers a root decision for a newly installed app.
 *
 * apd broadcasts here when it notices a package appear in packages.list, so the
 * choice is made while the app is on the user's mind instead of waiting to be
 * discovered in the SuperUser list.
 */
class InstallReceiver : BroadcastReceiver() {
    companion object {
        private const val TAG = "InstallReceiver"
        private const val CHANNEL_ID = "apatch_install"
        private const val NOTIFY_BASE = 10000
        const val ACTION_GRANT = "me.bmax.apatch.action.GRANT_ROOT"
        const val ACTION_EXCLUDE = "me.bmax.apatch.action.EXCLUDE_APP"
        const val ACTION_APP_UNINSTALLED = "me.bmax.apatch.ACTION_APP_UNINSTALLED"
    }

    override fun onReceive(context: Context, intent: Intent) {
        val pkg = intent.getStringExtra("pkg") ?: intent.getStringExtra("package_name") ?: return
        when (intent.action) {
            ACTION_GRANT -> applyDecision(context, pkg, grant = true)
            ACTION_EXCLUDE -> applyDecision(context, pkg, grant = false)
            ACTION_APP_UNINSTALLED -> dismiss(context, pkg)
            else -> notifyInstalled(context, pkg)
        }
    }

    private fun applyDecision(context: Context, pkg: String, grant: Boolean) {
        val uid = runCatching {
            context.packageManager.getApplicationInfo(pkg, 0).uid
        }.getOrElse {
            Log.w(TAG, "no uid for $pkg, it may already be gone", it)
            dismiss(context, pkg)
            return
        }

        thread {
            // The receiver can start the process cold, before APApplication's
            // own elevation has finished, and these calls need root.
            Natives.su()

            val sctx = if (grant) APApplication.MAGISK_SCONTEXT else APApplication.DEFAULT_SCONTEXT
            PkgConfig.changeConfig(
                PkgConfig.Config(
                    pkg,
                    if (grant) 0 else 1,
                    if (grant) 1 else 0,
                    Natives.Profile(uid, 0, sctx)
                )
            )
            if (grant) {
                Natives.grantSu(uid, 0, sctx)
                Natives.setUidExclude(uid, 0)
            } else {
                Natives.revokeSu(uid)
                Natives.setUidExclude(uid, 1)
            }
            dismiss(context, pkg)
        }
    }

    private fun notifyInstalled(context: Context, pkg: String) {
        val pm = context.packageManager
        val appName = runCatching {
            pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString()
        }.getOrDefault(pkg)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ID,
                    context.getString(R.string.notification_channel_app_install),
                    NotificationManager.IMPORTANCE_HIGH
                )
            )
        }

        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentTitle(context.getString(R.string.notification_app_installed_title, appName))
            .setContentText(context.getString(R.string.notification_grant_root_question))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .addAction(
                0,
                context.getString(R.string.notification_action_exclude),
                actionIntent(context, ACTION_EXCLUDE, pkg)
            )
            .addAction(
                0,
                context.getString(R.string.notification_action_grant),
                actionIntent(context, ACTION_GRANT, pkg)
            )
            .build()

        runCatching {
            NotificationManagerCompat.from(context).notify(notifyId(pkg), notification)
        }.onFailure {
            // POST_NOTIFICATIONS may not have been granted yet.
            Log.w(TAG, "could not post the install notification for $pkg", it)
        }
    }

    private fun actionIntent(context: Context, action: String, pkg: String) =
        PendingIntent.getBroadcast(
            context,
            pkg.hashCode() + action.hashCode(),
            Intent(context, InstallReceiver::class.java).apply {
                this.action = action
                putExtra("pkg", pkg)
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

    private fun notifyId(pkg: String) = NOTIFY_BASE + pkg.hashCode()

    private fun dismiss(context: Context, pkg: String) =
        NotificationManagerCompat.from(context).cancel(notifyId(pkg))
}
