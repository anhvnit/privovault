/// Hybrid Logical Clock.
///
/// Encoded as `<15-digit ms>-<4-hex counter>-<nodeId>` so that plain string
/// comparison (SQLite `>`/`<`, Dart compareTo) is a correct total order.
/// This is what makes row-level merge deterministic across devices.
///
/// Hardening:
///  * the counter never exceeds [maxCounter] (4 hex digits): on overflow the
///    clock moves to the next millisecond instead, so the fixed-width
///    encoding — and with it lexical ordering and `substr(hlc, 22)` — holds;
///  * [observe] refuses remote timestamps more than [maxDriftMs] ahead of the
///    local wall clock, so one device with a wrong (or malicious) clock
///    cannot drag every other device's clock into the future.
class HlcClock {
  HlcClock(this.nodeId, {int Function()? wallClock}) : _wall = wallClock ?? _now;

  final String nodeId;
  final int Function() _wall;
  int _ms = 0;
  int _counter = 0;

  /// Largest accepted clock skew of a remote timestamp (5 minutes).
  static const maxDriftMs = 5 * 60 * 1000;

  /// Largest counter that fits the 4-hex-digit encoding.
  static const maxCounter = 0xFFFF;

  static int _now() => DateTime.now().toUtc().millisecondsSinceEpoch;

  /// Current local wall-clock time used by this clock (ms since epoch, UTC).
  int wallMs() => _wall();

  /// Timestamp for a local write.
  String now() {
    final wall = _wall();
    if (wall > _ms) {
      _ms = wall;
      _counter = 0;
    } else {
      _counter++;
    }
    _normalize();
    return encode(_ms, _counter, nodeId);
  }

  /// Advance past a timestamp seen from another device (on merge).
  ///
  /// Returns false (and leaves the clock unchanged) when [remote] is not a
  /// well-formed HLC or lies more than [maxDriftMs] ahead of the wall clock.
  bool observe(String remote) {
    final r = decode(remote);
    if (r == null || r.counter > maxCounter || r.ms < 0) return false;
    final wall = _wall();
    if (r.ms > wall + maxDriftMs) return false;
    final maxMs = [wall, _ms, r.ms].reduce((a, b) => a > b ? a : b);
    if (maxMs == _ms && maxMs == r.ms) {
      _counter = (_counter > r.counter ? _counter : r.counter) + 1;
    } else if (maxMs == _ms) {
      _counter++;
    } else if (maxMs == r.ms) {
      _counter = r.counter + 1;
    } else {
      _counter = 0;
    }
    _ms = maxMs;
    _normalize();
    return true;
  }

  /// Raise the clock to at least [stored] — the highest HLC already in the
  /// local database — so the next local write sorts after every row we
  /// hold, even if the wall clock moved backwards since. Unlike [observe]
  /// there is no drift bound: these rows were validated when written or
  /// merged. Malformed input is ignored.
  void seed(String stored) {
    final r = decode(stored);
    if (r == null || r.counter > maxCounter || r.ms < 0) return;
    if (r.ms > _ms || (r.ms == _ms && r.counter > _counter)) {
      _ms = r.ms;
      _counter = r.counter;
    }
  }

  /// Counter overflow → next millisecond (keeps the 4-hex-digit width).
  void _normalize() {
    if (_counter > maxCounter) {
      _ms++;
      _counter = 0;
    }
  }

  /// True when [hlc] is well-formed and its physical time is at most
  /// [maxDriftMs] ahead of [nowMs].
  static bool acceptable(String hlc, int nowMs) {
    final r = decode(hlc);
    if (r == null || r.counter > maxCounter || r.ms < 0) return false;
    return r.ms <= nowMs + maxDriftMs;
  }

  static String encode(int ms, int counter, String node) =>
      '${ms.toString().padLeft(15, '0')}-${counter.toRadixString(16).padLeft(4, '0')}-$node';

  static ({int ms, int counter, String node})? decode(String s) {
    final parts = s.split('-');
    if (parts.length < 3) return null;
    final ms = int.tryParse(parts[0]);
    final c = int.tryParse(parts[1], radix: 16);
    if (ms == null || c == null) return null;
    return (ms: ms, counter: c, node: parts.sublist(2).join('-'));
  }

  /// Minimum possible HLC for a given time (useful as a "since" bound).
  static String floor(int ms) => encode(ms, 0, '');
}
