package dev.rourunisen.tapauth.service

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.SystemClock
import android.util.Log
import android.view.View
import android.widget.RemoteViews
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import dev.rourunisen.tapauth.TapAuthApplication
import dev.rourunisen.tapauth.data.AuthContextDisplay
import dev.rourunisen.tapauth.data.AuthRequest
import dev.rourunisen.tapauth.data.ContextSanitizer
import dev.rourunisen.tapauth.data.KeypairRepository
import dev.rourunisen.tapauth.data.TransportType
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Mac
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Manages pending authentication requests and coordinates between services and UI.
 *
 * This is the Android shell: it builds and posts the notification, broadcasts the request, and owns
 * the callback's coroutine scope. All the state lives in a [PendingRequestRegistry] of
 * [AndroidPrompt]; the registry holds no framework type and arms its own deadline sweep, so its
 * release properties can be unit-tested.
 */
class AuthRequestManager private constructor() {

    private val scope = CoroutineScope(Dispatchers.IO)

    /**
     * The prompt as this shell needs it: identity and deadline plus the two Android things the
     * release has to do something with, the callback and the context the banner was posted from.
     */
    private class AndroidPrompt(
        val authRequest: AuthRequest,
        val callback: (approved: Boolean, challenge: ByteArray?, explicitDenial: Boolean) -> Unit,
        val appContext: Context,
        override val bleDeviceAddress: String?,
        override val deadlineMs: Long,
    ) : PendingPrompt {
        override val requestId: String
            get() = authRequest.requestId

        override val challenge: ByteArray
            get() = authRequest.challenge
    }

    private val pending: PendingRequestRegistry<AndroidPrompt> =
        PendingRequestRegistry(
            clock = { SystemClock.elapsedRealtime() },
            // The deadline sweep. Registration arms it, so an entry cannot exist without one; the
            // sweep releases whatever is due, and a prompt another path already released costs it
            // nothing (it is not handed back twice).
            scheduleExpiry = { delayMs -> armExpiry(delayMs) },
        )

    /** The registry's scheduler: release every due prompt once [delayMs] has passed. */
    private fun armExpiry(delayMs: Long) {
        try {
            scope.launch {
                try {
                    delay(delayMs)
                    pending.releaseExpired().forEach { expired ->
                        Log.d(
                            TAG,
                            "Timeout reached; cancelling pending request ${expired.requestId}",
                        )
                        finish(expired, approved = false, challenge = null, explicitDenial = false)
                    }
                } catch (_: Exception) {}
            }
        } catch (_: Exception) {}
    }

    fun markCancelledChallenge(challenge: ByteArray) {
        pending.markCancelled(challenge)
        Log.d(TAG, "Marked challenge as cancelled (ttl=${PendingRequestRegistry.CANCEL_TTL_MS}ms)")
    }

    fun isChallengeCancelled(challenge: ByteArray): Boolean = pending.isCancelled(challenge)

    /**
     * Submit an authentication request for user approval Returns a request ID
     *
     * The four context parameters carry the Client's signed caller context (§3.3); they are
     * defaults so BLE/older call sites keep compiling, and they appear before [callback] because a
     * trailing lambda always binds to the last parameter.
     */
    fun submitRequest(
        context: Context,
        deviceId: String,
        deviceName: String,
        username: String,
        hostname: String,
        challenge: ByteArray,
        timestamp: Long,
        transportType: TransportType,
        bleDeviceAddress: String? = null, // Optional: BLE MAC address for disconnect cleanup
        pamService: String = "",
        processName: String = "",
        commandPreview: String = "",
        ttyPresent: Boolean = false,
        callback: (approved: Boolean, challenge: ByteArray?, explicitDenial: Boolean) -> Unit,
    ): String {
        // Derive stable notification ID from challenge bytes (SHA-256 -> first 4 bytes -> int)
        val notificationId = notificationIdFor(challenge)

        val requestId = UUID.randomUUID().toString()

        val authRequest =
            AuthRequest(
                requestId = requestId,
                deviceId = deviceId,
                deviceName = deviceName,
                username = username,
                hostname = hostname,
                challenge = challenge,
                timestamp = timestamp,
                transportType = transportType,
                pamService = pamService,
                processName = processName,
                commandPreview = commandPreview,
                ttyPresent = ttyPresent,
            )

        // The protocol-v2 caller context, as the desktop sent it: the renderers
        // (AuthContextDisplay) sanitize separately, and this line is what
        // scripts/test-e2e.sh asserts on. It lives here because submitRequest is the one
        // place both transports funnel through (AuthenticationService for UDP,
        // BleGattService for BLE), and because nothing else on the phone carries all three
        // values: the prompt shows the command preview *instead of* service/process, and the
        // BLE receipt line logs none of the three (only username/hostname/ttyPresent).
        //
        // The preview's *content* is logged only by the `e2e` build variant, via
        // BuildConfig.E2E_TESTING (app/build.gradle.kts decides it: false for release and
        // debug, true only for e2e). It is the desktop process's own argv, which routinely
        // carries `-p <password>`, `--token` or an `Authorization` header, and `Log.d` is not
        // stripped from release builds: emitting it would hand the credential to any
        // `adb logcat` capture or bug report. Every other build logs its length instead, so
        // the fact that a preview arrived survives without the argv. The E2E suite is the one
        // consumer that needs the content, and it installs the e2e variant.
        //
        // Each value is scrubbed first (see `scrubLogValue`): it derives from the caller's own
        // argv, so an unprivileged local user could otherwise embed a newline and forge extra
        // logcat lines, and a secret on that command line would be persisted here after the
        // prompt is gone. The tokens the E2E suite greps are plain ASCII and pass unchanged.
        // That formatting is still needed for the E2E form; the production form logs no value
        // to format.
        //
        // The `BuildConfig.E2E_TESTING` literal below is the one point in this path no automated
        // check covers: every JVM unit test runs against the e2e variant (`testBuildType = "e2e"`),
        // where the flag is true, so `callerContextLogLine`'s false branch is only ever exercised
        // by passing the flag as a parameter — never through this call. Nothing under `scripts/ci/`
        // looks at an APK or greps for `commandPreview` (it builds the Rust crates and scans the
        // distro payloads), so flipping this literal to `true` would ship the preview's content in
        // a `Log.d` that survives release with no check failing. A shipped-artifact check that the
        // release dex cannot contain the E2E-only marker string is what would close that gap.
        Log.d(
            TAG,
            callerContextLogLine(
                authRequest.pamService,
                authRequest.processName,
                authRequest.commandPreview,
                dev.rourunisen.tapauth.BuildConfig.E2E_TESTING,
            ),
        )

        // The prompt's deadline, decided once. The notification's `setTimeoutAfter` and the state
        // sweep below are the same number, so the banner and the entry cannot disagree about when
        // the prompt is over. `setTimeoutAfter(0)` means "no timeout", and a request already past
        // its session deadline therefore gets the shortest real timeout instead of a permanent
        // ongoing notification; a config read that fails falls back to that same minimum rather
        // than to "never expires".
        val remainingTimeout = runCatching {
            val sessionTimeoutMs =
                dev.rourunisen.tapauth.data.AppConfiguration.getInstance(context)
                    .sessionTimeoutSeconds * 1000
            (sessionTimeoutMs - (System.currentTimeMillis() - timestamp)).coerceAtLeast(1L)
        }
            .getOrElse { e ->
                Log.w(TAG, "Failed to read the session timeout; using the minimum: ${e.message}")
                1L
            }

        val request =
            AndroidPrompt(
                authRequest = authRequest,
                callback = callback,
                appContext = context.applicationContext,
                bleDeviceAddress = bleDeviceAddress,
                deadlineMs = pending.now() + remainingTimeout + EXPIRY_SLACK_MS,
            )
        // Registration is the one gate a promise to the client passes through: it refuses a
        // challenge whose cancel got in first, and arming the deadline sweep is part of storing the
        // entry, so a prompt cannot exist without one. Only a refusal is ours to answer - as
        // cancelled, never as an explicit denial, because nobody denied anything - and it posts
        // neither the broadcast nor the notification.
        when (pending.register(request)) {
            PendingRequestRegistry.Registration.Registered -> Unit
            PendingRequestRegistry.Registration.RefusedCancelled -> {
                Log.d(
                    TAG,
                    "Dropping submitRequest for already-cancelled challenge; no notification will be posted",
                )
                scope.launch { callback(false, null, false) }
                return UUID.randomUUID().toString()
            }
            PendingRequestRegistry.Registration.AlreadyClaimed -> {
                // The canceller claimed this request between the insert and the cancelled-challenge
                // check, so it has already delivered the client's one answer (and on BLE already
                // disconnected the link). Answering again would be a second denial for one request.
                Log.d(
                    TAG,
                    "Auth request $requestId was claimed by a concurrent cancel; not answering it again",
                )
                return requestId
            }
        }

        // Broadcast to MainActivity
        val intent =
            Intent(ACTION_AUTH_REQUEST).apply {
                putExtra(EXTRA_AUTH_REQUEST, authRequest)
                setPackage(context.packageName)
            }
        context.sendBroadcast(intent)

        // Also post a persistent notification so the user can tap to open the app and approve
        try {
            // Tap on notification body -> show biometric prompt directly (transparent activity)
            val biometricIntent =
                Intent(context, dev.rourunisen.tapauth.BiometricPromptActivity::class.java).apply {
                    action = ACTION_AUTH_REQUEST
                    putExtra(EXTRA_AUTH_REQUEST, authRequest)
                    flags =
                        Intent.FLAG_ACTIVITY_NEW_TASK or
                            Intent.FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS or
                            Intent.FLAG_ACTIVITY_NO_HISTORY or
                            Intent.FLAG_ACTIVITY_NO_USER_ACTION
                }

            // Use bytes-derived stable notification ID (already computed at function start)

            val pendingIntent =
                PendingIntent.getActivity(
                    context,
                    notificationId,
                    biometricIntent,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                )

            // Action: Approve -> opens BiometricPromptActivity to prompt for biometric verification
            val approveIntent =
                Intent(context, dev.rourunisen.tapauth.BiometricPromptActivity::class.java).apply {
                    action = ACTION_AUTH_REQUEST
                    putExtra(EXTRA_AUTH_REQUEST, authRequest)
                    flags =
                        Intent.FLAG_ACTIVITY_NEW_TASK or
                            Intent.FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS or
                            Intent.FLAG_ACTIVITY_NO_HISTORY or
                            Intent.FLAG_ACTIVITY_NO_USER_ACTION
                }
            val approvePending =
                PendingIntent.getActivity(
                    context,
                    (requestId + "_approve").hashCode(),
                    approveIntent,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                )

            // Action: Deny -> quick deny handled by BroadcastReceiver (no UI)
            // Create HMAC token over the request ID using the server private key to prevent
            // spoofing
            var hmacBytes: ByteArray? = null
            try {
                val keypairRepo = KeypairRepository(context)
                val hmacKey = keypairRepo.getOrCreateHmacKey()
                val mac = Mac.getInstance("HmacSHA256")
                mac.init(hmacKey)
                hmacBytes = mac.doFinal(requestId.toByteArray(Charsets.UTF_8))
            } catch (e: Exception) {
                Log.w(TAG, "Failed to compute HMAC for deny action: ${e.message}")
            }

            val denyBroadcast =
                Intent(context, dev.rourunisen.tapauth.service.AuthActionReceiver::class.java)
                    .apply {
                        action =
                            dev.rourunisen.tapauth.service.AuthActionReceiver
                                .ACTION_NOTIFICATION_ACTION
                        putExtra("notification_action", "deny")
                        putExtra(EXTRA_AUTH_REQUEST, authRequest)
                        hmacBytes?.let { putExtra("hmac", it) }
                    }
            val denyPending =
                PendingIntent.getBroadcast(
                    context,
                    (requestId + "_deny").hashCode(),
                    denyBroadcast,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
                )

            // §3.3: the primary header stays `username@hostname`; the secondary line below it is
            // the re-sanitized caller context, capped at two lines with an end ellipsis.
            val secondaryLine = AuthContextDisplay.contextLine(authRequest)
            // The identity strings are peer-chosen (`client_hostname` comes from the provision
            // payload), so the header is sanitized too rather than rendered verbatim.
            val displayUsername =
                ContextSanitizer.sanitize(username, AuthContextDisplay.IDENTITY_MAX_BYTES)
            val displayHostname =
                ContextSanitizer.sanitize(hostname, AuthContextDisplay.IDENTITY_MAX_BYTES)
            val displayDeviceName =
                ContextSanitizer.sanitize(deviceName, AuthContextDisplay.IDENTITY_MAX_BYTES)
            val contentViews =
                RemoteViews(
                        context.packageName,
                        dev.rourunisen.tapauth.R.layout.notification_auth_request,
                    )
                    .apply {
                        val titleId = dev.rourunisen.tapauth.R.id.notification_title
                        val contextId = dev.rourunisen.tapauth.R.id.notification_context
                        setTextViewText(titleId, "$displayUsername@$displayHostname")
                        if (secondaryLine.isEmpty()) {
                            setViewVisibility(contextId, View.GONE)
                        } else {
                            setTextViewText(contextId, secondaryLine)
                            setViewVisibility(contextId, View.VISIBLE)
                        }
                        // A custom content view does not inherit `setContentIntent`; wire the tap
                        // target explicitly so tapping the body still opens the prompt.
                        setOnClickPendingIntent(
                            dev.rourunisen.tapauth.R.id.notification_root,
                            pendingIntent,
                        )
                    }

            val notificationBuilder =
                NotificationCompat.Builder(context, TapAuthApplication.AUTH_CHANNEL_ID)
                    .setSmallIcon(dev.rourunisen.tapauth.R.drawable.ic_launcher_foreground)
                    .setContentTitle("Authentication request")
                    .setContentText("$displayDeviceName: $displayUsername@$displayHostname")
                    .setCustomContentView(contentViews)
                    // Clone so the collapsed and expanded views are distinct instances; both are
                    // this same two-row layout, so the summary never loses the context line.
                    .setCustomBigContentView(contentViews.clone())
                    .setContentIntent(pendingIntent)
                    .addAction(
                        dev.rourunisen.tapauth.R.drawable.ic_launcher_foreground,
                        "Approve",
                        approvePending,
                    )
                    .addAction(
                        dev.rourunisen.tapauth.R.drawable.ic_launcher_foreground,
                        "Deny",
                        denyPending,
                    )
                    .setOngoing(true)
                    .setAutoCancel(false)
                    .setPriority(NotificationCompat.PRIORITY_HIGH)
                    .setTimeoutAfter(remainingTimeout)

            // E2E-only: launch BiometricPromptActivity full-screen from the
            // notification (e.g. over the lock screen). Production builds hold no
            // USE_FULL_SCREEN_INTENT permission and rely on the heads-up
            // notification instead, so this must stay behind the e2e build flag.
            if (dev.rourunisen.tapauth.BuildConfig.E2E_TESTING) {
                notificationBuilder.setFullScreenIntent(pendingIntent, true)
            }

            val notification = notificationBuilder.build()

            // Deterministic prompt launch for automated E2E runs only.
            //
            // A background service cannot normally start an activity: Android 10+
            // blocks background activity starts. The E2E harness needs a
            // UI-independent path to the prompt, so this stays behind the e2e
            // build flag; production relies on the notification.
            if (dev.rourunisen.tapauth.BuildConfig.E2E_TESTING) {
                try {
                    context.startActivity(biometricIntent)
                    Log.d(TAG, "E2E build: launched BiometricPromptActivity for request $requestId")
                } catch (e: Exception) {
                    Log.d(
                        TAG,
                        "Direct activity launch not permitted from current context: ${e.message}",
                    )
                }
            }

            val challengeHex = challenge.joinToString("") { "%02x".format(it) }
            // `username`/`hostname` are the caller's own strings and `deviceName` the peer-supplied
            // hostname a pairing persisted, so each goes through [scrubLogValue] before it lands in
            // logcat — see the rationale on the caller-context line above.
            Log.d(
                TAG,
                "Posting auth notification (id=$notificationId) for ${scrubLogValue(deviceName)} @ " +
                    "${scrubLogValue(username)}@${scrubLogValue(hostname)}, " +
                    "challenge=${challengeHex.take(16)}...",
            )

            val nm = NotificationManagerCompat.from(context)
            try {
                if (nm.areNotificationsEnabled()) {
                    nm.notify(notificationId, notification)
                } else {
                    Log.w(TAG, "Notifications disabled; skipping notify (id=$notificationId)")
                }
            } catch (se: SecurityException) {
                Log.w(
                    TAG,
                    "Missing notification permission; skipping notify (id=$notificationId): ${se.message}",
                )
            }
            Log.d(TAG, "Posted auth notification (id=$notificationId)")
        } catch (e: Exception) {
            Log.w(TAG, "Failed to post auth request notification: ${e.message}")
        }

        Log.d(
            TAG,
            "Submitted auth request $requestId for ${scrubLogValue(username)}@${scrubLogValue(hostname)}",
        )

        return requestId
    }

    /**
     * Handle response from MainActivity (approved or denied)
     *
     * @param explicitDenial: true if user clicked "Deny", false if timeout/cancel
     */
    fun handleResponse(
        requestId: String,
        approved: Boolean,
        challenge: ByteArray?,
        explicitDenial: Boolean = false,
    ) {
        val request = pending.release(requestId)
        if (request != null) {
            Log.d(
                TAG,
                "Auth request $requestId ${if (approved) "approved" else if (explicitDenial) "explicitly denied" else "timed out/cancelled"}",
            )
            finish(request, approved, challenge, explicitDenial)
        } else {
            Log.w(TAG, "Received response for unknown request ID: $requestId")
        }
    }

    /**
     * Cancel one pending request by id, if it is still pending.
     *
     * This is NOT an explicit user denial: the client is answered as cancelled (`approved = false`,
     * `explicitDenial = false`). The deadline sweep releases expired entries itself, from the
     * scheduler [pending] was built with, so this is the API for cancelling a single request from
     * outside the manager rather than the timeout path.
     */
    fun cancelRequest(requestId: String) {
        val request = pending.release(requestId) ?: return
        Log.d(TAG, "Cancelled auth request $requestId (timeout)")
        finish(request, approved = false, challenge = null, explicitDenial = false)
    }

    /** Check if a pending request exists by ID */
    fun hasPendingRequest(requestId: String): Boolean = pending.has(requestId)

    /** Get all active request IDs */
    fun getActiveRequestIds(): Set<String> = pending.activeIds()

    /**
     * Cancel all pending requests that match the given challenge This is used when an
     * AuthenticationCancel message is received
     *
     * @param challenge The challenge bytes to match against
     * @return true if any requests were cancelled
     */
    fun cancelRequestsByChallenge(challenge: ByteArray): Boolean {
        val challengeHex = challenge.joinToString("") { "%02x".format(it) }
        Log.d(TAG, "cancelRequestsByChallenge: challenge=${challengeHex.take(16)}...")

        // Record the cancellation before the scan: a submit that lands between the scan and the
        // record would otherwise be neither released by this call nor dropped by its own
        // cancel check. The record outlives the call either way, so a cancel that matches nothing
        // still suppresses the request it was meant for.
        markCancelledChallenge(challenge)

        val released = pending.releaseByChallenge(challenge)
        if (released.isNotEmpty()) {
            Log.d(TAG, "Cancelling ${released.size} request(s) by challenge")
        }
        released.forEach { request ->
            Log.d(TAG, "Cancelled auth request ${request.requestId} due to AuthenticationCancel")
            finish(request, approved = false, challenge = null, explicitDenial = false)
        }

        return released.isNotEmpty()
    }

    /**
     * Cancel all pending requests associated with a BLE device whose GATT connection is gone.
     *
     * Called by BleGattService after a short reconnect grace period following a disconnect, so
     * transient link drops (which the device survives by reconnecting) never cancel a prompt the
     * user may be about to answer, while a link that stays down cannot leave an orphaned prompt
     * alive until the daemon timeout.
     *
     * @param bleDeviceAddress The BLE MAC address of the disconnected device
     * @return true if any requests were cancelled
     */
    fun cancelRequestsByBleDisconnection(bleDeviceAddress: String): Boolean {
        val released = pending.releaseByBleDevice(bleDeviceAddress)
        if (released.isEmpty()) return false

        Log.d(
            TAG,
            "BLE device $bleDeviceAddress stayed disconnected, cancelling ${released.size} pending request(s)",
        )

        released.forEach { request ->
            Log.d(TAG, "Cancelled auth request ${request.requestId} due to BLE disconnection")
            finish(request, approved = false, challenge = null, explicitDenial = false)
        }

        return true
    }

    /**
     * The side effects of a release: deliver the callback and dismiss the notification.
     *
     * Only reachable with an entry [PendingRequestRegistry] handed back, i.e. with the one claim
     * that won the release, so a second removal path for the same request cannot deliver a second
     * callback or leave a banner behind.
     */
    private fun finish(
        request: AndroidPrompt,
        approved: Boolean,
        challenge: ByteArray?,
        explicitDenial: Boolean,
    ) {
        // Launch callback on IO dispatcher to avoid NetworkOnMainThreadException: both transports'
        // callbacks write to a socket or a GATT link, and the callers include a receiver and
        // activities, so delivering inline would run that I/O on the main thread.
        scope.launch { request.callback(approved, challenge, explicitDenial) }

        try {
            val notificationId = notificationIdFor(request.challenge)
            Log.d(
                TAG,
                "Cancelling notification for request ${request.requestId} (id=$notificationId)",
            )
            NotificationManagerCompat.from(request.appContext).cancel(notificationId)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to dismiss notification for ${request.requestId}: ${e.message}")
        }
    }

    companion object {
        private const val TAG = "AuthRequestManager"

        /**
         * The only amount by which the entry can outlive the banner.
         *
         * The entry's deadline is `registration + remainingTimeout + EXPIRY_SLACK_MS`, while
         * `setTimeoutAfter(remainingTimeout)` counts from when the notification is posted, so the
         * overshoot is `EXPIRY_SLACK_MS - postingLatency`: the slack is the bound and the latency
         * only shrinks it. A notification whose construction takes longer than this gap releases
         * the entry first, which costs nothing but a tap landing on [handleResponse]'s unknown-id
         * path.
         */
        private const val EXPIRY_SLACK_MS = 250L

        // Notification IDs are derived from the challenge bytes (see [notificationIdFor]) so
        // several prompts can coexist and be dismissed individually.

        const val ACTION_AUTH_REQUEST = "dev.rourunisen.tapauth.AUTH_REQUEST"
        const val EXTRA_AUTH_REQUEST = "auth_request"

        @Volatile private var instance: AuthRequestManager? = null

        fun getInstance(): AuthRequestManager {
            return instance
                ?: synchronized(this) { instance ?: AuthRequestManager().also { instance = it } }
        }

        /**
         * Compute a stable, deterministic notification ID from challenge bytes. Uses SHA-256 and
         * maps the first 4 bytes to a non-negative Int.
         */
        fun notificationIdFor(challenge: ByteArray): Int {
            return try {
                val challengeHex = challenge.joinToString("") { "%02x".format(it) }
                val digest = java.security.MessageDigest.getInstance("SHA-256").digest(challenge)
                val b0 = (digest[0].toInt() and 0xFF)
                val b1 = (digest[1].toInt() and 0xFF)
                val b2 = (digest[2].toInt() and 0xFF)
                val b3 = (digest[3].toInt() and 0xFF)
                val raw = (b0 shl 24) or (b1 shl 16) or (b2 shl 8) or b3
                val notificationId = raw and 0x7FFFFFFF // ensure non-negative
                Log.d(
                    TAG,
                    "notificationIdFor: challenge=${challengeHex.take(16)}... → id=$notificationId",
                )
                notificationId
            } catch (_: Exception) {
                // Fallback: use Kotlin contentHashCode masked to positive
                (challenge.contentHashCode() and 0x7FFFFFFF)
            }
        }

        /** Delay in ms before debug auto-approval fires when no biometrics are enrolled. */
        const val DEBUG_AUTO_APPROVE_DELAY_MS = 1000L

        /**
         * E2E-build-only auto-approval used when no biometrics are enrolled.
         *
         * Called from the `BuildConfig.E2E_TESTING` branch of the biometric availability checks in
         * [dev.rourunisen.tapauth.MainActivity] and
         * [dev.rourunisen.tapauth.BiometricPromptActivity] (which pass their own
         * `onGracePeriodElapsed`). Waits [DEBUG_AUTO_APPROVE_DELAY_MS] so the E2E harness can
         * inject an explicit denial broadcast first, then approves if the request is still pending.
         */
        fun autoApproveInE2e(
            activity: FragmentActivity,
            authRequest: AuthRequest,
            canAuthStrong: Int,
            onGracePeriodElapsed: () -> Unit = {},
        ) {
            Log.i(
                TAG,
                "Biometrics not enrolled in E2E test mode (strong=$canAuthStrong); auto-approving after grace period if not denied",
            )
            activity.lifecycleScope.launch {
                delay(DEBUG_AUTO_APPROVE_DELAY_MS)
                if (getInstance().hasPendingRequest(authRequest.requestId)) {
                    Log.i(TAG, "Auto-approving request ${authRequest.requestId} in E2E test mode")
                    approveRequest(activity, authRequest)
                }
                onGracePeriodElapsed()
            }
        }

        /**
         * Submits an approved response for [authRequest] through AuthRequestManager.
         *
         * v2 signs only the WrapperMessage: Rust computes the single Ed25519 signature over the
         * grant (via `createGrantWrapperMessage`), so the raw 32-byte challenge is what the
         * callback must carry. Signing it here as well would replace the challenge with a 64-byte
         * signature and every approval would fail verification.
         */
        fun approveRequest(context: Context, authRequest: AuthRequest) {
            try {
                Log.d(
                    TAG,
                    "Approving challenge (trunc): ${authRequest.challenge.take(8).joinToString("") { "%02x".format(it) }}…",
                )
                getInstance()
                    .handleResponse(
                        authRequest.requestId,
                        approved = true,
                        challenge = authRequest.challenge,
                    )
            } catch (e: Exception) {
                Log.e(TAG, "Failed to submit approval", e)
                getInstance()
                    .handleResponse(
                        authRequest.requestId,
                        approved = false,
                        challenge = null,
                        explicitDenial = false,
                    )
            }
        }
    }
}

/**
 * What the owning structure needs to know about a prompt: its identity, the two keys the views
 * match on, and its own deadline. Nothing here is an Android type, and the payload a caller needs
 * back at release time (a `Context`, a callback) stays in the caller's own record - the registry is
 * parameterised over it ([T]) rather than storing it as a nullable field the registry can never
 * reach for.
 */
internal interface PendingPrompt {
    val requestId: String
    val challenge: ByteArray
    val bleDeviceAddress: String?
    val deadlineMs: Long
}

/**
 * The one owning structure for pending prompts, with no Android framework type in its state.
 *
 * A prompt used to be spread over four co-equal maps (by id, by Base64 challenge, by BLE address,
 * plus the cancel records), each of which every removal path had to clean by hand, so one missed
 * clean silently broke a *different* feature: a missed id leaked a prompt no timeout would ever
 * collect, a missed index entry made the phone's Cancel stop working for that prompt. Here the
 * entry is the state, [release] is the only way out of the map, and the challenge/device views are
 * computed by scanning it — so the views cannot disagree with the map, and there is nothing to
 * forget.
 *
 * [clock] is injected and [scheduleExpiry] is the only way anything later than this call happens:
 * registration arms it, so "every entry is released by its deadline" is a property of [register]
 * rather than something each call site has to remember. Cancellation compares challenge bytes with
 * `contentEquals` rather than a Base64 key: under `unitTests.isReturnDefaultValues = true`
 * (app/build.gradle.kts) `android.util.Base64.encodeToString` returns null and
 * `SystemClock.elapsedRealtime` returns 0, so either would make this class untestable off-device.
 *
 * The realistic population is 1–3 prompts (`sessionTimeoutSeconds` defaults to 120 s and a UDP
 * burst is at most 3 per 2 s), which is what makes the scan cheaper than the bookkeeping — the old
 * code's own "in case index missed older entries" fallback scan said the same.
 */
internal class PendingRequestRegistry<T : PendingPrompt>(
    private val clock: () -> Long,
    private val scheduleExpiry: (delayMs: Long) -> Unit,
) {

    private val pending = ConcurrentHashMap<String, T>()

    /** Recently cancelled challenges (by content) and when the cancel was seen, in [clock]. */
    private val cancelledChallenges = ConcurrentHashMap<List<Byte>, Long>()

    /** What [register] did with the prompt it was handed. */
    enum class Registration {
        /** Stored and swept: the prompt is answerable until its deadline. */
        Registered,

        /**
         * Its challenge had been cancelled: nothing is stored, nothing is armed, the entry is the
         * caller's to answer as cancelled.
         */
        RefusedCancelled,

        /**
         * A canceller claimed the entry between the insert and the cancelled-challenge check and
         * has already answered it: nothing is stored and nothing is armed, and the caller must
         * **not** answer it again - the client has its one response for this request.
         */
        AlreadyClaimed,
    }

    /** The clock the deadlines and the cancel window are measured on. */
    fun now(): Long = clock()

    /**
     * Stores [request] as answerable, arming its deadline sweep; or reports why it did not.
     *
     * The cancelled-challenge check runs *after* the insert, which is what closes the window
     * between a submit and a cancel that raced it. The canceller marks before it scans, so a cancel
     * whose scan missed this entry marked before the insert, and this re-check sees that mark;
     * survival would need the scan to precede the insert and this check to precede the mark, i.e.
     * scan < insert < re-check < mark, which contradicts the canceller's mark < scan.
     *
     * The re-check also has to tell apart the two ways the insert can fail to stand: nobody had the
     * entry ([Registration.RefusedCancelled], so the caller owes the client an answer) and the
     * canceller already claimed and answered it ([Registration.AlreadyClaimed], so nothing is owed
     * and a second answer would be a duplicate denial on the wire).
     */
    fun register(request: T): Registration {
        pending[request.requestId] = request
        if (!isCancelled(request.challenge)) {
            // `delay(0)` returns immediately and a negative delay would be no wait at all, i.e. a
            // prompt nothing ever collects, so a deadline already behind the clock still gets a
            // real wait. Armed last: a registration that did not stand leaves no sweep behind.
            scheduleExpiry((request.deadlineMs - clock()).coerceAtLeast(1L))
            return Registration.Registered
        }
        // The identity check is the claim itself: if the rollback removes the very entry that was
        // inserted, this call is the one that took it back; if it removes nothing, another path
        // (the canceller's scan) claimed it and now owns this request's single answer.
        return if (pending.remove(request.requestId) === request) {
            Registration.RefusedCancelled
        } else {
            Registration.AlreadyClaimed
        }
    }

    fun find(requestId: String): T? = pending[requestId]

    fun has(requestId: String): Boolean = pending.containsKey(requestId)

    /** An immutable snapshot: the caller can neither mutate nor outlive the registry's state. */
    fun activeIds(): Set<String> = pending.keys.toSet()

    /**
     * Atomically claims [requestId] out of the registry and hands it back.
     *
     * This is the only way a prompt stops being pending, and [ConcurrentHashMap.remove] gives the
     * entry to exactly one caller: a second release of the same id - a duplicate response, a sweep
     * racing a dismissal - returns null and runs no side effect.
     */
    fun release(requestId: String): T? = pending.remove(requestId)

    /** Claims and returns every prompt carrying [challenge]; empty when none does. */
    fun releaseByChallenge(challenge: ByteArray): List<T> = claimAll {
        it.challenge.contentEquals(challenge)
    }

    /** Claims and returns every prompt registered on [bleDeviceAddress]. */
    fun releaseByBleDevice(bleDeviceAddress: String): List<T> = claimAll {
        it.bleDeviceAddress == bleDeviceAddress
    }

    /** Claims and returns every prompt whose deadline has passed at [now]; idempotent. */
    fun releaseExpired(now: Long = clock()): List<T> = claimAll {
        now >= it.deadlineMs
    }

    /**
     * Claims every entry matching [predicate].
     *
     * The claim is per entry and atomic, so a concurrently released entry is simply not returned
     * here, and an entry that another thread claims between the scan and this call is not returned
     * twice.
     */
    private fun claimAll(predicate: (T) -> Boolean): List<T> {
        val claimed = mutableListOf<T>()
        for (request in pending.values) {
            if (predicate(request) && claim(request)) claimed += request
        }
        return claimed
    }

    /**
     * Removes [request] and reports whether this call was the one that removed it: `remove` hands
     * the value to exactly one caller, and the identity check keeps the release honest if the same
     * id were ever reused for a later prompt.
     */
    private fun claim(request: T): Boolean = pending.remove(request.requestId) === request

    /** Remembers [challenge] as cancelled for [CANCEL_TTL_MS] from [now]. */
    fun markCancelled(challenge: ByteArray) {
        val now = clock()
        cancelledChallenges[challenge.toList()] = now
        pruneCancelledChallenges(now)
    }

    /** Whether [challenge] was cancelled within the last [CANCEL_TTL_MS]. */
    fun isCancelled(challenge: ByteArray): Boolean {
        val now = clock()
        pruneCancelledChallenges(now)
        return cancelledChallenges.containsKey(challenge.toList())
    }

    /** Drops cancel records older than [CANCEL_TTL_MS], so the map cannot grow without bound. */
    fun pruneCancelledChallenges(now: Long = clock()) {
        cancelledChallenges.entries.removeIf { (_, ts) -> now - ts > CANCEL_TTL_MS }
    }

    companion object {
        /** How long a cancellation intent outlives the message that carried it, in ms. */
        const val CANCEL_TTL_MS = 10_000L
    }
}

private fun ByteArray.toHexPreview(maxBytes: Int = 8): String {
    val take = kotlin.math.min(this.size, maxBytes)
    return this.take(take).joinToString("") { "%02x".format(it) } +
        if (this.size > take) "…" else ""
}

/** The `commandPreview=` value every non-E2E build logs: the size, and never the argv. */
private fun previewFact(commandPreview: String): String =
    "<${commandPreview.length} chars, E2E build only>"

/**
 * Build the `Auth request caller context:` line [AuthRequestManager.submitRequest] logs.
 *
 * [includeCommandPreview] is `BuildConfig.E2E_TESTING` at the call site, and it gates the preview
 * *content* only: the preview is the desktop process's own argv, which carries `-p <password>`,
 * `--token` and `Authorization` headers in ordinary use, and `Log.d` survives into release builds,
 * so logging it would leak the credential into any `adb logcat` capture or bug report. The `e2e`
 * build variant — which `scripts/test-e2e.sh` installs — gets the content so the suite can prove
 * `command_preview` was derived by the daemon and delivered to the phone; release and debug log
 * [previewFact] instead.
 *
 * The flag is a parameter rather than a `BuildConfig` read because `testBuildType = "e2e"`
 * (app/build.gradle.kts) makes `BuildConfig.E2E_TESTING` true in every JVM unit test, so a test
 * that read it directly could only ever exercise the E2E branch.
 *
 * Values are scrubbed by [scrubLogValue] before interpolation (newlines, control characters, the
 * 200-character cap) — see the rationale there; the E2E form needs that formatting because it still
 * logs the value.
 */
internal fun callerContextLogLine(
    pamService: String,
    processName: String,
    commandPreview: String,
    includeCommandPreview: Boolean,
): String =
    "Auth request caller context: pamService=${scrubLogValue(pamService)}, " +
        "processName=${scrubLogValue(processName)}, commandPreview=" +
        if (includeCommandPreview) scrubLogValue(commandPreview) else previewFact(commandPreview)
