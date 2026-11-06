package com.privovault.crypto

import androidx.fragment.app.FragmentActivity
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding

/**
 * Registered automatically by GeneratedPluginRegistrant.
 * The host activity must be a FragmentActivity (FlutterFragmentActivity)
 * for BiometricPrompt; otherwise unlock fails with code "unavailable".
 */
class PrivovaultCryptoPlugin : FlutterPlugin, ActivityAware {
    private var bridge: VaultKeyBridge? = null

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        bridge = VaultKeyBridge(binding.applicationContext, binding.binaryMessenger)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        bridge?.dispose()
        bridge = null
    }

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        bridge?.activity = binding.activity as? FragmentActivity
    }

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) = onAttachedToActivity(binding)

    override fun onDetachedFromActivityForConfigChanges() {
        bridge?.activity = null
    }

    override fun onDetachedFromActivity() {
        bridge?.activity = null
    }
}
