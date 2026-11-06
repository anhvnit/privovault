import Flutter

/// Registered automatically by GeneratedPluginRegistrant.
public class PrivovaultCryptoPlugin: NSObject, FlutterPlugin {
  public static func register(with registrar: FlutterPluginRegistrar) {
    VaultKeyBridge.register(with: registrar.messenger())
  }
}
