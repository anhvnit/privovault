import Flutter
import Foundation
import LocalAuthentication
import Security

/// Biometric ↔ Keychain handshake for the 256-bit Master Key (MK).
///
/// The MK is a Keychain generic-password item protected by
///   kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly  — never in iCloud/iTunes
///                                                       backups, never synced,
///                                                       erased if passcode removed
///   SecAccessControl(.biometryCurrentSet)             — the Secure Enclave only
///                                                       releases it after a live
///                                                       FaceID/TouchID match, and
///                                                       invalidates it if a new
///                                                       face/finger is enrolled.
///
/// There is no "if authenticated { return key }" branch in app code: the
/// SecItemCopyMatching call *is* the biometric check, enforced by securityd.
/// (Secure Enclave keys themselves are P-256 only, so a symmetric MK is held
/// as an SE-gated Keychain item — Apple's documented pattern.)
final class VaultKeyBridge: NSObject {
  /// Keychain service; keep stable across releases or existing vaults become unreadable.
  private static let service = "com.privovault.app.mk"
  private static let account = "master-key-v1"
  /// Second slot used to make MK replacement atomic (see `store`).
  private static let accountNext = "master-key-v1.next"
  private static let existedFlag = "com.privovault.mk.created" // distinguishes "invalidated" from "never created"
  /// Which slot holds the CURRENT key, written right after a successful
  /// SecItemAdd and before the old slot is deleted. Without it, a crash in
  /// between left both items and `unlock` always preferred `account` — on
  /// every other rotation that silently brought back the OLD key. Not a
  /// secret (a slot name); absent on older installs → legacy preference.
  private static let liveSlotFlag = "com.privovault.mk.liveSlot"
  private static var instance: VaultKeyBridge?

  private let queue = DispatchQueue(label: "com.privovault.keychain", qos: .userInitiated)

  static func register(with messenger: FlutterBinaryMessenger) {
    let channel = FlutterMethodChannel(name: "privovault_crypto/key_release", binaryMessenger: messenger)
    let bridge = VaultKeyBridge()
    instance = bridge
    channel.setMethodCallHandler { call, result in bridge.handle(call, result) }
  }

  private func handle(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
    let args = call.arguments as? [String: Any] ?? [:]
    let reason = args["reason"] as? String ?? "Unlock your vault"
    switch call.method {
    case "status": result(["hasKey": hasKey(), "biometry": biometryName()])
    case "create": queue.async { self.store(Self.randomKey(), returning: true, result) }
    case "import":
      guard let data = (args["key"] as? FlutterStandardTypedData)?.data, data.count == 32 else {
        return result(FlutterError(code: "unknown", message: "Key must be 32 bytes", details: nil))
      }
      queue.async { self.store(data, returning: false, result) }
    case "unlock": queue.async { self.unlock(reason: reason, result) }
    case "destroy":
      SecItemDelete(baseQuery(Self.account) as CFDictionary)
      SecItemDelete(baseQuery(Self.accountNext) as CFDictionary)
      UserDefaults.standard.removeObject(forKey: Self.existedFlag)
      UserDefaults.standard.removeObject(forKey: Self.liveSlotFlag)
      result(nil)
    case "excludeFromBackup":
      guard let path = args["path"] as? String else { return result(nil) }
      var url = URL(fileURLWithPath: path)
      var values = URLResourceValues()
      values.isExcludedFromBackup = true
      try? url.setResourceValues(values)
      result(nil)
    default: result(FlutterMethodNotImplemented)
    }
  }

  // MARK: - Store

  /// Atomic from the app's perspective. Two Keychain accounts act as slots;
  /// the LIVE one is the recorded slot (`liveSlotFlag`), else `account` if
  /// it exists, else `accountNext` (`unlock` uses the same preference). The new MK is added under the OTHER slot
  /// first; only when SecItemAdd succeeded is the old slot deleted, then we
  /// reply. If SecItemAdd fails the old item was never touched. A crash
  /// between add and delete leaves both items; `unlock` then returns the
  /// preferred one, and the Dart side settles the pending rotation by
  /// whichever key actually opens private.db (both outcomes are consistent
  /// because Dart only discards its pending files on a confirmed cancel).
  /// No relabel (SecItemUpdate on an access-controlled item) is needed.
  private func store(_ key: Data, returning: Bool, _ result: @escaping FlutterResult) {
    var error: NSError?
    guard LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
      return reply(result, FlutterError(code: Self.code(for: error), message: error?.localizedDescription, details: nil))
    }
    var cfErr: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
      nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .biometryCurrentSet, &cfErr
    ) else {
      return reply(result, FlutterError(code: "unavailable", message: "Access control unavailable", details: nil))
    }
    let live = liveAccount()
    let target = (live == Self.account) ? Self.accountNext : Self.account
    SecItemDelete(baseQuery(target) as CFDictionary) // stale leftover of an interrupted attempt
    var add = baseQuery(target)
    add[kSecValueData as String] = key
    add[kSecAttrAccessControl as String] = access
    add[kSecAttrSynchronizable as String] = kCFBooleanFalse
    let status = SecItemAdd(add as CFDictionary, nil)
    guard status == errSecSuccess else {
      return reply(result, FlutterError(code: "unknown", message: "SecItemAdd \(status)", details: nil))
    }
    UserDefaults.standard.set(true, forKey: Self.existedFlag)
    // Point at the new slot BEFORE deleting the old one (see liveSlotFlag).
    UserDefaults.standard.set(target, forKey: Self.liveSlotFlag)
    UserDefaults.standard.synchronize()
    if let old = live { SecItemDelete(baseQuery(old) as CFDictionary) }
    reply(result, returning ? FlutterStandardTypedData(bytes: key) : nil)
  }

  // MARK: - Unlock (the handshake)

  private func unlock(reason: String, _ result: @escaping FlutterResult) {
    let context = LAContext()
    context.localizedReason = reason
    context.localizedFallbackTitle = "" // biometrics only; no passcode fallback for the vault
    // An invalidated (.biometryCurrentSet) item vanishes, so with no live
    // slot this falls through to errSecItemNotFound below.
    var query = baseQuery(liveAccount() ?? Self.account)
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    query[kSecUseAuthenticationContext as String] = context

    var item: CFTypeRef?
    // Blocks this background queue while FaceID/TouchID is presented.
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    switch status {
    case errSecSuccess:
      guard let data = item as? Data, data.count == 32 else {
        return reply(result, FlutterError(code: "unknown", message: "Corrupt key item", details: nil))
      }
      reply(result, FlutterStandardTypedData(bytes: data))
    case errSecUserCanceled:
      reply(result, FlutterError(code: "cancelled", message: nil, details: nil))
    case errSecAuthFailed:
      reply(result, FlutterError(code: "lockout", message: "Biometric authentication failed", details: nil))
    case errSecItemNotFound:
      // .biometryCurrentSet items vanish when enrollment changes.
      let existed = UserDefaults.standard.bool(forKey: Self.existedFlag)
      reply(result, FlutterError(code: existed ? "invalidated" : "notFound", message: nil, details: nil))
    default:
      reply(result, FlutterError(code: "unknown", message: "SecItemCopyMatching \(status)", details: nil))
    }
  }

  // MARK: - Helpers

  private func hasKey() -> Bool { liveAccount() != nil }

  /// Probe (without prompting) whether an item exists under [account].
  private func exists(_ account: String) -> Bool {
    let context = LAContext()
    context.interactionNotAllowed = true // probe without prompting
    var q = baseQuery(account)
    q[kSecUseAuthenticationContext as String] = context
    let s = SecItemCopyMatching(q as CFDictionary, nil)
    return s == errSecSuccess || s == errSecInteractionNotAllowed
  }

  /// The slot `unlock` reads: the recorded live slot if its item exists,
  /// else `account`, else `accountNext` (older installs).
  private func liveAccount() -> String? {
    if let recorded = UserDefaults.standard.string(forKey: Self.liveSlotFlag),
       recorded == Self.account || recorded == Self.accountNext,
       exists(recorded) {
      return recorded
    }
    if exists(Self.account) { return Self.account }
    if exists(Self.accountNext) { return Self.accountNext }
    return nil
  }

  private func biometryName() -> String {
    let ctx = LAContext()
    guard ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) else { return "none" }
    switch ctx.biometryType {
    case .faceID: return "faceId"
    case .touchID: return "touchId"
    default:
      if #available(iOS 17.0, *), ctx.biometryType == .opticID { return "opticId" }
      return "none"
    }
  }

  private func baseQuery(_ account: String) -> [String: Any] {
    [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: Self.service,
      kSecAttrAccount as String: account,
    ]
  }

  private static func randomKey() -> Data {
    var bytes = [UInt8](repeating: 0, count: 32)
    let rc = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
    precondition(rc == errSecSuccess, "CSPRNG failure")
    return Data(bytes)
  }

  private static func code(for error: NSError?) -> String {
    guard let e = error, e.domain == LAError.errorDomain else { return "unavailable" }
    switch LAError.Code(rawValue: e.code) {
    case .biometryNotEnrolled: return "notEnrolled"
    case .biometryLockout: return "lockout"
    case .passcodeNotSet: return "notEnrolled"
    default: return "unavailable"
    }
  }

  private func reply(_ result: @escaping FlutterResult, _ value: Any?) {
    DispatchQueue.main.async { result(value) }
  }
}
