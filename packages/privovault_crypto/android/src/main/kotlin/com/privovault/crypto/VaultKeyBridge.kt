package com.privovault.crypto

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.io.File
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Biometric ↔ Android Keystore handshake (plugin side of HardwareBoundKeyRelease) for the 256-bit Master Key (MK).
 *
 * A non-exportable AES-256-GCM *wrapping key* lives in the Keystore (StrongBox
 * secure element when present, else TEE) with:
 *   setUserAuthenticationRequired(true) + AUTH_BIOMETRIC_STRONG, timeout 0
 *     → every single use needs a fresh Class-3 biometric match
 *   setInvalidatedByBiometricEnrollment(true)
 *     → a newly enrolled fingerprint/face destroys the key
 *   setUnlockedDeviceRequired(true)
 *
 * The MK is stored only as AES-GCM ciphertext in noBackupFilesDir (excluded
 * from Auto Backup). Unwrapping requires BiometricPrompt with a CryptoObject:
 * the TEE refuses Cipher.doFinal() unless *that cipher instance* was
 * authorised by the biometric hardware. No boolean "authenticated" flag in
 * app code can be patched to bypass it.
 */
class VaultKeyBridge(
    private val context: Context,
    messenger: BinaryMessenger,
) : MethodChannel.MethodCallHandler {

    /** Set by the plugin while an activity is attached (BiometricPrompt needs one). */
    var activity: FragmentActivity? = null

    private companion object {
        const val ALIAS = "qlv_mk_wrap_v1"
        const val ALIAS_B = "qlv_mk_wrap_v1b"
        const val KEYSTORE = "AndroidKeyStore"
        const val TRANSFORM = "AES/GCM/NoPadding"
        const val FLAG_FILE = "mk.created"
        const val SLOT_FILE = "mk.slot"
    }

    /**
     * Two key slots so that replacing the MK (Emergency Kit rotation, restore)
     * is atomic: the new wrapping key + blob go into the INACTIVE slot, and
     * only after the biometric prompt succeeded and the blob is on disk is
     * `mk.slot` atomically renamed to point at it (the commit point). The old
     * slot is deleted afterwards. A cancelled prompt, an error or a crash
     * before the commit leaves the old key and `mk.wrapped` untouched.
     * Slot A = legacy (ALIAS, mk.wrapped), so existing installs keep working.
     */
    private data class Slot(val id: String, val alias: String, val file: File)

    private val slotA get() = Slot("a", ALIAS, File(context.noBackupFilesDir, "mk.wrapped"))
    private val slotB get() = Slot("b", ALIAS_B, File(context.noBackupFilesDir, "mk.wrapped.b"))
    private val slotFile get() = File(context.noBackupFilesDir, SLOT_FILE)
    private val flagFile get() = File(context.noBackupFilesDir, FLAG_FILE)

    private fun activeSlot(): Slot {
        val id = runCatching { if (slotFile.exists()) slotFile.readText().trim() else "a" }.getOrDefault("a")
        return if (id == "b") slotB else slotA
    }

    private fun otherSlot(s: Slot) = if (s.id == "a") slotB else slotA

    /** write-to-temp + rename (atomic replace on the same filesystem). */
    private fun atomicWrite(target: File, bytes: ByteArray) {
        val tmp = File(target.parentFile, target.name + ".tmp")
        java.io.FileOutputStream(tmp).use { out ->
            out.write(bytes)
            out.fd.sync()
        }
        if (!tmp.renameTo(target)) {
            tmp.delete()
            throw java.io.IOException("rename failed: ${target.name}")
        }
    }

    private fun deleteSlot(s: Slot) {
        runCatching { keyStore().deleteEntry(s.alias) }
        s.file.delete()
    }
    private val channel = MethodChannel(messenger, "privovault_crypto/key_release")

    init {
        channel.setMethodCallHandler(this)
    }

    fun dispose() = channel.setMethodCallHandler(null)

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        val reason = call.argument<String>("reason") ?: "Unlock your vault"
        try {
            when (call.method) {
                "status" -> result.success(mapOf("hasKey" to hasKey(), "biometry" to biometryName()))
                "create" -> {
                    val mk = ByteArray(32).also { SecureRandom().nextBytes(it) }
                    wrapAndStore(mk, reason, result, returnKey = true)
                }
                "import" -> {
                    val mk = call.argument<ByteArray>("key")
                    if (mk == null || mk.size != 32) return result.error("unknown", "Key must be 32 bytes", null)
                    wrapAndStore(mk, reason, result, returnKey = false)
                }
                "unlock" -> unwrap(reason, result)
                "destroy" -> { destroy(); result.success(null) }
                "excludeFromBackup" -> result.success(null) // no per-file flag on Android: allowBackup="false" + no_backup.xml / data_extraction_rules.xml exclude every domain (cloud + device transfer)
                else -> result.notImplemented()
            }
        } catch (e: Exception) {
            result.error("unknown", e.message, null)
        }
    }

    // ------------------------------------------------------------- create

    private fun wrapAndStore(mk: ByteArray, reason: String, result: MethodChannel.Result, returnKey: Boolean) {
        val availability = BiometricManager.from(context).canAuthenticate(BIOMETRIC_STRONG)
        if (availability != BiometricManager.BIOMETRIC_SUCCESS) {
            return result.error(availabilityCode(availability), "Class-3 biometrics unavailable", null)
        }
        // Never touch the live slot before the commit (see [Slot]).
        val live = activeSlot()
        val target = otherSlot(live)
        deleteSlot(target) // stale leftovers of an earlier interrupted attempt
        val cipher: Cipher = try {
            val key = generateWrappingKey(target.alias)
            Cipher.getInstance(TRANSFORM).apply { init(Cipher.ENCRYPT_MODE, key) }
        } catch (e: Exception) {
            deleteSlot(target)
            return result.error("unknown", e.message, null)
        }
        var committed = false
        authenticate(cipher, "Secure your vault", reason, result, onFail = { if (!committed) deleteSlot(target) }) { authed ->
            val ct = authed.doFinal(mk)
            atomicWrite(target.file, authed.iv + ct) // iv(12) || ciphertext+tag
            atomicWrite(slotFile, target.id.toByteArray()) // COMMIT
            committed = true
            runCatching { flagFile.writeText("1") }
            runCatching { deleteSlot(live) }
            result.success(if (returnKey) mk.copyOf() else null)
            mk.fill(0)
        }
    }

    private fun generateWrappingKey(alias: String): SecretKey {
        fun spec(strongBox: Boolean): KeyGenParameterSpec {
            val b = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                b.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            } else {
                @Suppress("DEPRECATION") b.setUserAuthenticationValidityDurationSeconds(-1)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                b.setUnlockedDeviceRequired(true)
                if (strongBox) b.setIsStrongBoxBacked(true)
            }
            return b.build()
        }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        val wantStrongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        return try {
            gen.init(spec(wantStrongBox)); gen.generateKey()
        } catch (e: StrongBoxUnavailableException) {
            gen.init(spec(false)); gen.generateKey()
        }
    }

    // ------------------------------------------------------------- unlock

    private fun unwrap(reason: String, result: MethodChannel.Result) {
        val slot = activeSlot()
        val blob = if (slot.file.exists()) slot.file.readBytes() else null
        val key = keyStore().getKey(slot.alias, null) as? SecretKey
        if (blob == null || key == null || blob.size < 12 + 16) {
            return result.error(if (flagFile.exists()) "invalidated" else "notFound", null, null)
        }
        val cipher = Cipher.getInstance(TRANSFORM)
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, blob, 0, 12))
        } catch (e: KeyPermanentlyInvalidatedException) {
            destroy(keepFlag = true)
            return result.error("invalidated", "Biometric enrollment changed", null)
        }
        authenticate(cipher, "Unlock vault", reason, result) { authed ->
            val mk = authed.doFinal(blob, 12, blob.size - 12)
            result.success(mk)
        }
    }

    // ------------------------------------------------------------ prompt

    private fun authenticate(
        cipher: Cipher,
        title: String,
        subtitle: String,
        result: MethodChannel.Result,
        onFail: () -> Unit = {},
        onAuthed: (Cipher) -> Unit,
    ) {
        val host = activity
        if (host == null) {
            onFail()
            return result.error("unavailable", "No foreground activity for the biometric prompt", null)
        }
        val prompt = BiometricPrompt(host, ContextCompat.getMainExecutor(host),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(r: BiometricPrompt.AuthenticationResult) {
                    val authed = r.cryptoObject?.cipher
                    if (authed == null) {
                        onFail()
                        return result.error("unknown", "No CryptoObject returned", null)
                    }
                    try {
                        onAuthed(authed)
                    } catch (e: Exception) {
                        runCatching { onFail() }
                        result.error("unknown", e.message, null)
                    }
                }

                override fun onAuthenticationError(code: Int, msg: CharSequence) {
                    runCatching { onFail() }
                    result.error(promptCode(code), msg.toString(), null)
                }
                // onAuthenticationFailed = one non-matching attempt; the prompt stays open.
            })
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setNegativeButtonText("Cancel")
            .setAllowedAuthenticators(BIOMETRIC_STRONG)
            .setConfirmationRequired(false)
            .build()
        prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
    }

    // ------------------------------------------------------------ helpers

    private fun keyStore() = KeyStore.getInstance(KEYSTORE).apply { load(null) }

    private fun hasKey(): Boolean {
        val s = activeSlot()
        return s.file.exists() && keyStore().containsAlias(s.alias)
    }

    private fun destroy(keepFlag: Boolean = false) {
        deleteSlot(slotA)
        deleteSlot(slotB)
        slotFile.delete()
        if (!keepFlag) flagFile.delete()
    }

    private fun biometryName(): String {
        if (BiometricManager.from(context).canAuthenticate(BIOMETRIC_STRONG) != BiometricManager.BIOMETRIC_SUCCESS) return "none"
        val pm = context.packageManager
        return if (!pm.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT) && pm.hasSystemFeature(PackageManager.FEATURE_FACE)) "face" else "fingerprint"
    }

    private fun availabilityCode(c: Int) = when (c) {
        BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> "notEnrolled"
        else -> "unavailable"
    }

    private fun promptCode(c: Int) = when (c) {
        BiometricPrompt.ERROR_USER_CANCELED, BiometricPrompt.ERROR_NEGATIVE_BUTTON, BiometricPrompt.ERROR_CANCELED -> "cancelled"
        BiometricPrompt.ERROR_LOCKOUT, BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> "lockout"
        BiometricPrompt.ERROR_NO_BIOMETRICS -> "notEnrolled"
        BiometricPrompt.ERROR_HW_NOT_PRESENT, BiometricPrompt.ERROR_HW_UNAVAILABLE -> "unavailable"
        else -> "unknown"
    }
}
