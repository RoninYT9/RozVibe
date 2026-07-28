// lib/core/search/search_index_database.dart
import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:sqflite/sqflite.dart';
import 'package:path/path.dart' as p;

final searchIndexDatabaseProvider = Provider<SearchIndexDatabase>((ref) {
  return SearchIndexDatabase();
});

/// Local SQLite database acting as a blind index for encrypted diary entries.
/// Stores HMAC-SHA256 hashes of content tokens mapped to Firestore entry IDs.
/// This is a performance optimization layer — it never stores plaintext.
class SearchIndexDatabase {
  Database? _db;

  bool get isOpen => _db != null;

  /// Opens or creates the blind index database.
  Future<void> initialize() async {
    if (_db != null) return;

    final dbPath = await getDatabasesPath();
    final path = p.join(dbPath, 'rozvibe_search.db');

    _db = await openDatabase(
      path,
      version: 1,
      onCreate: (db, version) async {
        await db.execute('''
          CREATE TABLE blind_index (
            entry_id TEXT NOT NULL,
            token_hash TEXT NOT NULL
          )
        ''');
        await db.execute(
          'CREATE INDEX IF NOT EXISTS idx_token_hash ON blind_index(token_hash)',
        );
        debugPrint('SearchIndexDB: Created blind_index table with index.');
      },
    );
    debugPrint('SearchIndexDB: Initialized.');
  }

  /// Returns the count of rows in the blind_index table.
  /// Used to determine if a backfill is needed on first launch after upgrade.
  Future<int> getIndexCount() async {
    _assertOpen();
    final result = await _db!.rawQuery('SELECT COUNT(*) as cnt FROM blind_index');
    return Sqflite.firstIntValue(result) ?? 0;
  }

  /// Indexes an entry by replacing its old hashes with new ones.
  /// Uses a transaction for atomicity.
  Future<void> indexEntry(String entryId, List<String> tokenHashes) async {
    _assertOpen();
    if (tokenHashes.isEmpty) return;

    await _db!.transaction((txn) async {
      // Remove old hashes for this entry
      await txn.delete('blind_index', where: 'entry_id = ?', whereArgs: [entryId]);
      // Batch-insert new hashes
      final batch = txn.batch();
      for (final hash in tokenHashes) {
        batch.insert('blind_index', {'entry_id': entryId, 'token_hash': hash});
      }
      await batch.commit(noResult: true);
    });
  }

  /// Batch-indexes multiple entries in a single transaction.
  /// Used for the one-time backfill on first launch after upgrade.
  Future<void> batchIndexEntries(Map<String, List<String>> entryHashes) async {
    _assertOpen();
    if (entryHashes.isEmpty) return;

    await _db!.transaction((txn) async {
      final batch = txn.batch();
      for (final entry in entryHashes.entries) {
        for (final hash in entry.value) {
          batch.insert('blind_index', {'entry_id': entry.key, 'token_hash': hash});
        }
      }
      await batch.commit(noResult: true);
    });
    debugPrint('SearchIndexDB: Batch-indexed ${entryHashes.length} entries.');
  }

  /// Searches the blind index for entry IDs matching ANY of the query hashes.
  /// Returns a list of distinct entry IDs.
  Future<List<String>> search(List<String> queryHashes) async {
    _assertOpen();
    if (queryHashes.isEmpty) return const [];

    // Build parameterized IN clause
    final placeholders = List.filled(queryHashes.length, '?').join(',');
    final results = await _db!.rawQuery(
      'SELECT DISTINCT entry_id FROM blind_index WHERE token_hash IN ($placeholders)',
      queryHashes,
    );

    return results.map((row) => row['entry_id'] as String).toList();
  }

  /// Removes all hashes for a specific entry.
  Future<void> deleteEntry(String entryId) async {
    _assertOpen();
    await _db!.delete('blind_index', where: 'entry_id = ?', whereArgs: [entryId]);
  }

  /// Truncates the entire blind index. Used when user deletes all entries.
  Future<void> deleteAll() async {
    _assertOpen();
    await _db!.delete('blind_index');
    debugPrint('SearchIndexDB: All index data cleared.');
  }

  /// Closes the database connection.
  Future<void> close() async {
    await _db?.close();
    _db = null;
  }

  void _assertOpen() {
    if (_db == null) {
      throw StateError('SearchIndexDatabase not initialized. Call initialize() first.');
    }
  }
}
