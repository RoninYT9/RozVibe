import 'dart:convert';
import 'dart:typed_data';
import 'package:encrypt/encrypt.dart' as encrypt_pkg;
import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:pointycastle/export.dart';

Uint8List _deriveKeyInIsolate(Map<String, Uint8List> args) {
  final password = args['password']!;
  final salt = args['salt']!;
  final derivator = PBKDF2KeyDerivator(HMac(SHA256Digest(), 64))
    ..init(Pbkdf2Parameters(salt, 100000, 76));
  return derivator.process(password);
}

final encryptionServiceProvider = Provider<EncryptionService>((ref) {
  return EncryptionService();
});

class EncryptionService {
  final _storage = const FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );
  
  encrypt_pkg.Key? _key;
  encrypt_pkg.IV? _legacyIv;
  Uint8List? _searchKey; // NEW: 32-byte HMAC key for blind index

  bool get isInitialized => _key != null && _searchKey != null;

  /// Retrieves the raw bytes of the AES key and Legacy IV for isolate transfer.
  Map<String, Uint8List>? get keyMaterial {
    if (_key == null || _legacyIv == null) return null;
    return {
      'key': _key!.bytes,
      'legacyIv': _legacyIv!.bytes,
    };
  }

  /// Initializes the service instantly for background Isolate execution.
  void initializeForIsolate(Uint8List keyBytes, Uint8List legacyIvBytes) {
    _key = encrypt_pkg.Key(keyBytes);
    _legacyIv = encrypt_pkg.IV(legacyIvBytes);
    // Note: _searchKey is not needed for simple decryption in isolate
  }

  /// The raw search key bytes for the blind index tokenizer.
  /// Returns null if not initialized.
  Uint8List? get searchKeyBytes => _searchKey;

  /// Initializes the encryption key, legacy IV, and search key.
  /// 
  /// PBKDF2 derives 76 bytes total:
  ///   [0:32]  → AES-256 key (unchanged from previous 44-byte derivation)
  ///   [32:44] → Legacy fallback IV (unchanged from previous 44-byte derivation)
  ///   [44:76] → HMAC-SHA256 search key (NEW)
  ///
  /// BACKWARD COMPATIBILITY: PBKDF2 output is generated in independent 32-byte
  /// blocks. Block 1 = bytes 0–31, Block 2 = bytes 32–63. Extending from 44 to
  /// 76 bytes does NOT change the first 44 bytes. All existing encrypted data
  /// decrypts identically.
  Future<void> initialize(String userId, {String? pin, String? manualSalt}) async {
    String? salt = manualSalt;
    
    // If no manual salt provided, try to read from local storage
    salt ??= await _storage.read(key: 'crypto_salt_$userId');
    
    // If still null, generate a new one (first time user or device)
    if (salt == null) {
      final random = encrypt_pkg.IV.fromSecureRandom(16);
      salt = random.base64;
      await _storage.write(key: 'crypto_salt_$userId', value: salt);
    } else {
      // Ensure local storage is in sync even if salt came from cloud
      await _storage.write(key: 'crypto_salt_$userId', value: salt);
    }

    final password = utf8.encode('${userId}_${pin ?? "default_secure_vault"}');
    final decodedSalt = base64.decode(salt);

    // Check if we have the derived key cached securely
    final cacheKey = 'crypto_derived_$userId';
    final cachedDerived = await _storage.read(key: cacheKey);
    Uint8List derivedBytes;

    if (cachedDerived != null) {
      // Use cached key to bypass slow PBKDF2
      derivedBytes = base64.decode(cachedDerived);
    } else {
      // Derive 76 bytes: 32 (AES key) + 12 (legacy IV) + 32 (search key)
      derivedBytes = await compute(_deriveKeyInIsolate, {
        'password': Uint8List.fromList(password),
        'salt': Uint8List.fromList(decodedSalt),
      });
      // Save it securely so we never have to run PBKDF2 again for this user on this device
      await _storage.write(key: cacheKey, value: base64.encode(derivedBytes));
    }

    _key = encrypt_pkg.Key(derivedBytes.sublist(0, 32));       // Bytes 0–31: AES key
    _legacyIv = encrypt_pkg.IV(derivedBytes.sublist(32, 44));  // Bytes 32–43: Legacy IV
    _searchKey = Uint8List.fromList(derivedBytes.sublist(44, 76)); // Bytes 44–75: Search key
  }

  /// Returns the current salt from local storage.
  Future<String?> getSalt(String userId) async {
    return await _storage.read(key: 'crypto_salt_$userId');
  }

  /// Encrypts plain text. Generated a random IV for each encryption and prepends it.
  String encryptString(String plainText) {
    if (_key == null) throw Exception('Encryption NOT initialized.');
    
    final iv = encrypt_pkg.IV.fromSecureRandom(12); // GCM standard IV size
    final encrypter = encrypt_pkg.Encrypter(encrypt_pkg.AES(_key!, mode: encrypt_pkg.AESMode.gcm));
    
    final encrypted = encrypter.encrypt(plainText, iv: iv);
    
    // Combine IV (12 bytes) + Ciphertext + Tag
    final combined = Uint8List(iv.bytes.length + encrypted.bytes.length);
    combined.setAll(0, iv.bytes);
    combined.setAll(iv.bytes.length, encrypted.bytes);
    
    return base64.encode(combined);
  }

  /// Decrypts a base64 encoded string that has [IV(12b) + Data].
  String decryptString(String cipherText) {
    if (_key == null) throw Exception('Encryption NOT initialized.');
    if (cipherText.isEmpty) return '';

    try {
      final combined = base64.decode(cipherText);
      if (combined.length < 12) return cipherText; // Not enough data for IV

      final iv = encrypt_pkg.IV(combined.sublist(0, 12));
      final encryptedBytes = combined.sublist(12);
      
      final encrypter = encrypt_pkg.Encrypter(encrypt_pkg.AES(_key!, mode: encrypt_pkg.AESMode.gcm));
      return encrypter.decrypt(encrypt_pkg.Encrypted(encryptedBytes), iv: iv);
    } catch (e) {
      // Fallback: If it's an old entry or failed to decrypt with new format, try old static IV logic
      // This ensures we don't break existing data even if it was "gibberish"
      return _decryptLegacy(cipherText);
    }
  }

  /// Decrypts using the old static IV logic as a fallback.
  String _decryptLegacy(String cipherText) {
    if (_legacyIv == null) return cipherText;
    try {
      final encrypter = encrypt_pkg.Encrypter(encrypt_pkg.AES(_key!, mode: encrypt_pkg.AESMode.gcm));
      return encrypter.decrypt64(cipherText, iv: _legacyIv!);
    } catch (_) {
      return cipherText;
    }
  }

  String encryptData(dynamic data) => encryptString(jsonEncode(data));

  dynamic decryptData(String cipherText) {
    final decrypted = decryptString(cipherText);
    try {
      return jsonDecode(decrypted);
    } catch (e) {
      return decrypted;
    }
  }
  
  /// Wipes all key material from memory.
  void clear() {
    _key = null;
    _legacyIv = null;
    _searchKey = null; // Wipe search key on logout
  }
}
