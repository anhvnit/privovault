import 'package:uuid/uuid.dart';

const _uuid = Uuid();

/// UUIDv7: time-ordered, generated offline, safe to merge across devices.
String newId() => _uuid.v7();
