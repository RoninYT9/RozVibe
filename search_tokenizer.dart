// lib/core/search/search_tokenizer.dart
import 'dart:convert';
import 'dart:typed_data';
import 'package:pointycastle/export.dart';

/// Utility for normalizing text into tokens and hashing them with HMAC-SHA256.
/// Used exclusively for the blind index — never touches encryption/decryption.
class SearchTokenizer {
  SearchTokenizer._();

  /// Punctuation regex: matches anything that isn't a letter, number, or whitespace.
  static final RegExp _punctuation = RegExp(r'[^\p{L}\p{N}\s]', unicode: true);

  /// Normalizes plaintext into deduplicated, lowercase word tokens.
  /// Filters out single-character tokens (too common to be useful for search).
  static List<String> tokenize(String plainText) {
    if (plainText.isEmpty) return const [];

    final normalized = plainText
        .toLowerCase()
        .replaceAll(_punctuation, ' ') // strip punctuation
        .replaceAll(RegExp(r'\s+'), ' ')  // collapse whitespace
        .trim();

    if (normalized.isEmpty) return const [];

    final tokens = normalized
        .split(' ')
        .where((t) => t.length > 1) // skip single-char tokens
        .toSet()                      // deduplicate
        .toList();

    return tokens;
  }

  /// Hashes each token with HMAC-SHA256 keyed by [searchKey].
  /// Returns a list of lowercase hex strings.
  static List<String> hashTokens(List<String> tokens, Uint8List searchKey) {
    if (tokens.isEmpty || searchKey.isEmpty) return const [];

    final hmac = HMac(SHA256Digest(), 64)
      ..init(KeyParameter(searchKey));

    return tokens.map((token) {
      final tokenBytes = Uint8List.fromList(utf8.encode(token));
      hmac.reset();
      final output = Uint8List(hmac.macSize);
      hmac.update(tokenBytes, 0, tokenBytes.length);
      hmac.doFinal(output, 0);
      return _toHex(output);
    }).toList();
  }

  /// Converts bytes to lowercase hex string.
  static String _toHex(Uint8List bytes) {
    final sb = StringBuffer();
    for (final b in bytes) {
      sb.write(b.toRadixString(16).padLeft(2, '0'));
    }
    return sb.toString();
  }
}
