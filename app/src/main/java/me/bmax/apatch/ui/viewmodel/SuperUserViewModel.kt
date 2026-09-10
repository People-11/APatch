package me.bmax.apatch.ui.viewmodel

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.graphics.drawable.Drawable
import android.os.IBinder
import android.os.Parcelable
import android.util.Log
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import com.topjohnwu.superuser.Shell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.parcelize.Parcelize
import me.bmax.apatch.APApplication
import me.bmax.apatch.IAPRootService
import me.bmax.apatch.Natives
import me.bmax.apatch.apApp
import me.bmax.apatch.services.RootServices
import me.bmax.apatch.util.APatchCli
import me.bmax.apatch.util.HanziToPinyin
import me.bmax.apatch.util.PkgConfig
import java.text.Collator
import java.util.Locale
import kotlin.concurrent.thread
import kotlin.coroutines.resume


class SuperUserViewModel : ViewModel() {
    companion object {
        private const val TAG = "SuperUserViewModel"

        /** PackageManager.MATCH_ANY_USER, which is not in the public SDK. */
        private const val MATCH_ANY_USER = 0x00400000

        /**
         * How long to wait for the root service before listing packages without
         * it. Generous enough for a cold start (the service forks a new
         * app_process as root), short enough not to look hung.
         */
        private const val ROOT_SERVICE_TIMEOUT_MS = 5000L

        private val appsLock = Any()
        var apps by mutableStateOf<List<AppInfo>>(emptyList())

        fun getAppIconDrawable(context: Context, packageName: String): Drawable? {
            val appList = synchronized(appsLock) { apps }
            val appDetail = appList.find { it.packageName == packageName }
            return appDetail?.packageInfo?.applicationInfo?.loadIcon(context.packageManager)
        }
    }

    @Parcelize
    data class AppInfo(
        val label: String,
        val pinyin: String,
        val packageInfo: PackageInfo,
        val config: PkgConfig.Config
    ) : Parcelable {
        val packageName: String
            get() = packageInfo.packageName
        val uid: Int
            get() = packageInfo.applicationInfo!!.uid
    }

    var search by mutableStateOf("")
    var showSystemApps by mutableStateOf(false)
    var isRefreshing by mutableStateOf(false)
        private set

    private val collator = Collator.getInstance(Locale.getDefault())

    private val sortedList by derivedStateOf {
        val comparator = compareBy<AppInfo> {
            when {
                it.config.allow != 0 -> 0
                it.config.exclude == 1 -> 1
                else -> 2
            }
        }.then(compareBy(collator, AppInfo::label))
        apps.sortedWith(comparator)
    }

    val appList by derivedStateOf {
        val query = search.lowercase()
        sortedList.filter {
            it.label.lowercase().contains(query) || it.packageName.lowercase()
                .contains(query) || it.pinyin.contains(query)
        }.filter {
            it.uid == 2000 // Always show shell
                    || showSystemApps || it.packageInfo.applicationInfo!!.flags.and(ApplicationInfo.FLAG_SYSTEM) == 0
        }.filter {
            it.packageName != apApp.packageName
        }
    }

    // Cancellable so the timeout in fetchPackages can actually abandon the wait;
    // a plain suspendCoroutine would keep the continuation alive and blow up
    // with "already resumed" if the service connected after we gave up.
    private suspend inline fun connectRootService(
        crossinline onDisconnect: () -> Unit = {}
    ): Pair<IBinder, ServiceConnection> = suspendCancellableCoroutine { continuation ->
        val connection = object : ServiceConnection {
            override fun onServiceDisconnected(name: ComponentName?) {
                onDisconnect()
            }

            override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
                if (continuation.isActive) {
                    continuation.resume(binder as IBinder to this)
                }
            }
        }
        val intent = Intent(apApp, RootServices::class.java)
        val task = RootServices.bindOrTask(
            intent,
            Shell.EXECUTOR,
            connection,
        )
        val shell = APatchCli.SHELL
        task?.let { it1 -> shell.execTask(it1) }
    }

    private fun stopRootService() {
        val intent = Intent(apApp, RootServices::class.java)
        RootServices.stop(intent)
    }

    // The root service can never come up — no root yet, a wedged shell, a denied
    // request — and there is no callback for that, so the bind just hangs and the
    // app list stays empty forever. Give it a bounded wait and then ask the plain
    // PackageManager instead: grant and exclude state comes from the kernel
    // either way, only the package list itself is less complete.
    private suspend fun fetchPackages(): List<PackageInfo> {
        val fromRoot = withTimeoutOrNull(ROOT_SERVICE_TIMEOUT_MS) {
            runCatching {
                val result = connectRootService { Log.w(TAG, "RootService disconnected") }
                val packages = IAPRootService.Stub.asInterface(result.first).getPackages(0).list
                withContext(Dispatchers.Main) { stopRootService() }
                packages
            }.onFailure { Log.e(TAG, "root package query failed", it) }.getOrNull()
        }
        if (fromRoot != null) return fromRoot

        Log.w(TAG, "root service unavailable, listing packages without it")
        // MATCH_ANY_USER is hidden from the SDK and needs INTERACT_ACROSS_USERS,
        // which we may not hold; fall through to the current user on refusal.
        val fallback = runCatching { apApp.packageManager.getInstalledPackages(MATCH_ANY_USER) }
            .getOrElse { apApp.packageManager.getInstalledPackages(0) }
        // The mapping below dereferences applicationInfo; drop entries without
        // one instead of failing the whole list on a single odd package.
        return fallback.filter { it.applicationInfo != null }
    }

    suspend fun fetchAppList() {
        isRefreshing = true

        try {
            withContext(Dispatchers.IO) {
                val allPackages = fetchPackages()

                val uids = Natives.suUids().toList()
                Log.d(TAG, "all allows: $uids")

                var configs: HashMap<Int, PkgConfig.Config> = HashMap()
                thread {
                    Natives.su()
                    configs = PkgConfig.readConfigs()
                }.join()

                Log.d(TAG, "all configs: $configs")

                val newApps = allPackages.map {
                    val appInfo = it.applicationInfo
                    val uid = appInfo!!.uid
                    val actProfile = if (uids.contains(uid)) Natives.suProfile(uid) else null
                    val config = configs.getOrDefault(
                        uid, PkgConfig.Config(appInfo.packageName, Natives.isUidExcluded(uid), 0, Natives.Profile(uid = uid))
                    )
                    config.allow = 0

                    // from kernel
                    if (actProfile != null) {
                        config.allow = 1
                        config.profile = actProfile
                    }
                    val label = appInfo.loadLabel(apApp.packageManager).toString()
                    AppInfo(
                        label = label,
                        // Pinyin is only needed for search filtering; converting is
                        // expensive, so do it once here instead of per keystroke.
                        pinyin = HanziToPinyin.getInstance().toPinyinString(label),
                        packageInfo = it,
                        config = config
                    )
                }

                withContext(Dispatchers.Main) {
                    synchronized(appsLock) {
                        apps = newApps
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to fetch app list", e)
        } finally {
            isRefreshing = false
        }
    }

    // Replaces the app's config wholesale so the snapshot state holding `apps`
    // invalidates and the UI recomposes; mutating Config fields in place would
    // leave the list showing stale grant/exclude state after a refresh.
    private fun updateAppConfig(app: AppInfo, newConfig: PkgConfig.Config) {
        synchronized(appsLock) {
            // Grant/exclude are per-UID operations; every package sharing the
            // UID must show the new state, or its stale row could overwrite it.
            apps = apps.map {
                if (it.uid == app.uid) it.copy(config = newConfig.copy(pkg = it.packageName)) else it
            }
        }
    }

    fun setRootGranted(app: AppInfo, granted: Boolean) {
        val config = app.config
        val newConfig = if (granted) {
            config.copy(
                allow = 1,
                exclude = 0,
                profile = config.profile.copy(uid = app.uid, scontext = APApplication.MAGISK_SCONTEXT)
            )
        } else {
            config.copy(allow = 0, profile = config.profile.copy(uid = app.uid))
        }
        PkgConfig.changeConfig(newConfig)
        if (granted) {
            Natives.grantSu(app.uid, 0, newConfig.profile.scontext)
            Natives.setUidExclude(app.uid, 0)
        } else {
            Natives.revokeSu(app.uid)
        }
        updateAppConfig(app, newConfig)
    }

    fun setExcluded(app: AppInfo, excluded: Boolean) {
        val config = app.config
        val newConfig = if (excluded) {
            config.copy(
                allow = 0,
                exclude = 1,
                profile = config.profile.copy(uid = app.uid, scontext = APApplication.DEFAULT_SCONTEXT)
            )
        } else {
            config.copy(exclude = 0, profile = config.profile.copy(uid = app.uid))
        }
        if (excluded) {
            Natives.revokeSu(app.uid)
        }
        PkgConfig.changeConfig(newConfig)
        Natives.setUidExclude(app.uid, newConfig.exclude)
        updateAppConfig(app, newConfig)
    }
}
