import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:archive/archive.dart';
import 'package:crypto/crypto.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';
import 'package:pointycastle/export.dart'
  show AESEngine, CBCBlockCipher, KeyParameter, PaddedBlockCipherImpl,
    PaddedBlockCipherParameters, PKCS7Padding, ParametersWithIV;
import 'package:sqflite/sqflite.dart';

const _assetName = 'assets/stolen_contacts_master.db3.enc';
const _bundledFilename = 'stolen_contacts_master.db';
const _password = 'HGGI h;fv ,ggi hgpl] rg hu,` fvf hgkhs';
const _arabicLetters = 'ابتثجحخدذرزسشصضطظعغفقكلمنهويى';
const _latinLetters = 'tvjHKdorszxSDTZugfqklmnhwyYpa';

extension _FirstOrNull<T> on Iterable<T> {
  T? get firstOrNull {
    final iterator = this.iterator;
    return iterator.moveNext() ? iterator.current : null;
  }
}

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const AdenContactsApp());
}

class AdenContactsApp extends StatelessWidget {
  const AdenContactsApp({super.key});

  @override
  Widget build(BuildContext context) {
    const ink = Color(0xFF17252A);
    const teal = Color(0xFF137C78);
    const coral = Color(0xFFDE765D);
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'دليل عدن',
      theme: ThemeData(
        useMaterial3: true,
        scaffoldBackgroundColor: const Color(0xFFF4F5F0),
        colorScheme: ColorScheme.fromSeed(
          seedColor: teal,
          primary: teal,
          secondary: coral,
          surface: const Color(0xFFFFFEFA),
          onSurface: ink,
        ),
        fontFamily: 'sans-serif',
        appBarTheme: const AppBarTheme(
          backgroundColor: Color(0xFFF4F5F0),
          foregroundColor: ink,
          elevation: 0,
          centerTitle: false,
        ),
        inputDecorationTheme: InputDecorationTheme(
          filled: true,
          fillColor: const Color(0xFFFFFEFA),
          border: OutlineInputBorder(
            borderRadius: BorderRadius.circular(12),
            borderSide: BorderSide.none,
          ),
          enabledBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(12),
            borderSide: const BorderSide(color: Color(0xFFD9E0DC)),
          ),
          focusedBorder: OutlineInputBorder(
            borderRadius: BorderRadius.circular(12),
            borderSide: const BorderSide(color: teal, width: 1.5),
          ),
        ),
      ),
      builder: (context, child) => Directionality(
        textDirection: TextDirection.rtl,
        child: child ?? const SizedBox.shrink(),
      ),
      home: const ContactsHomePage(),
    );
  }
}

enum NameSearchMode {
  exact('مطابق تمامًا', 'يطابق الاسم كاملًا', Icons.check_circle_outline),
  starts('يبدأ بـ', 'يبدأ الاسم بعبارة البحث', Icons.first_page),
  ends('ينتهي بـ', 'ينتهي الاسم بعبارة البحث', Icons.last_page),
  contains('يحتوي على', 'تظهر الأحرف في أي موضع', Icons.search),
  exactWord('الكلمة نفسها', 'مطابقة كلمة مستقلة', Icons.short_text),
  smart('بحث ذكي', 'ترتيب النتائج بحسب الصلة', Icons.auto_awesome);

  const NameSearchMode(this.label, this.description, this.icon);
  final String label;
  final String description;
  final IconData icon;
}

class ContactRecord {
  const ContactRecord({
    required this.name,
    required this.phone,
    this.count = 1,
    required this.source,
  });

  final String name;
  final String phone;
  final int count;
  final String source;
}

class DatabaseInfo {
  const DatabaseInfo({
    required this.fileName,
    required this.displayName,
    required this.tableName,
    required this.recordCount,
    required this.sizeMb,
    this.isBundled = false,
  });

  final String fileName;
  final String displayName;
  final String tableName;
  final int recordCount;
  final double sizeMb;
  final bool isBundled;
}

class _DatabaseHandle {
  const _DatabaseHandle({
    required this.info,
    required this.db,
    required this.nameColumn,
    required this.phoneColumn,
    required this.countColumn,
  });

  final DatabaseInfo info;
  final Database db;
  final String nameColumn;
  final String phoneColumn;
  final String? countColumn;
}

class ContactStore {
  ContactStore._();
  static final ContactStore instance = ContactStore._();

  final List<_DatabaseHandle> _databases = [];
  Future<void>? _initialization;

  bool get isReady => _databases.isNotEmpty;
  List<DatabaseInfo> get infos => _databases.map((item) => item.info).toList();

  Future<void> initialize() => _initialization ??= _initialize();

  Future<void> _initialize() async {
    final directory = await getApplicationDocumentsDirectory();
    final databaseDirectory = Directory(p.join(directory.path, 'contacts_dbs'));
    await databaseDirectory.create(recursive: true);
    final bundledFile = File(p.join(databaseDirectory.path, _bundledFilename));
    if (!await bundledFile.exists()) {
      await _extractBundledDatabase(bundledFile);
    }

    final files = databaseDirectory
        .listSync()
        .whereType<File>()
        .where((file) => p.extension(file.path).toLowerCase() == '.db');
    for (final file in files) {
      await _openDatabase(file, isBundled: p.basename(file.path) == _bundledFilename);
    }
  }

  Future<void> _extractBundledDatabase(File destination) async {
    final encrypted = await rootBundle.load(_assetName);
    final bytes = Uint8List.view(
      encrypted.buffer,
      encrypted.offsetInBytes,
      encrypted.lengthInBytes,
    );
    if (bytes.length < 32) throw const FormatException('ملف قاعدة البيانات المشفر غير مكتمل.');
    final iv = bytes.sublist(0, 16);
    final salt = Uint8List.fromList([0x43, 0x87, 0x23, 0x72, 0x20, 0x76, 0x55, 0x10]);
    final key = _pbkdf2(utf8.encode(_password), salt, 10000, 32);
    final cipher = PaddedBlockCipherImpl(
      PKCS7Padding(),
      CBCBlockCipher(AESEngine()),
    )..init(false, PaddedBlockCipherParameters<ParametersWithIV<KeyParameter>, Null>(
        ParametersWithIV<KeyParameter>(KeyParameter(key), iv),
        null,
      ));
    final zipBytes = cipher.process(Uint8List.fromList(bytes.sublist(16)));
    final archive = ZipDecoder().decodeBytes(zipBytes);
    final entry = archive.files.where((file) => file.name.toLowerCase().endsWith('.db3')).firstOrNull;
    if (entry == null) throw const FormatException('لم توجد قاعدة SQLite داخل الأرشيف.');
    final output = File('${destination.path}.tmp');
    await output.writeAsBytes(entry.content as List<int>, flush: true);
    final db = await openDatabase(output.path, readOnly: true);
    final tables = await _findSchema(db);
    await db.close();
    if (tables == null) {
      await output.delete();
      throw const FormatException('بنية قاعدة البيانات غير متوافقة.');
    }
    if (await destination.exists()) await destination.delete();
    await output.rename(destination.path);
  }

  static Uint8List _pbkdf2(List<int> password, List<int> salt, int iterations, int length) {
    final hmac = Hmac(sha256, password);
    final result = <int>[];
    for (var blockIndex = 1; result.length < length; blockIndex++) {
      final counter = ByteData(4)..setUint32(0, blockIndex, Endian.big);
      final blockInput = <int>[...salt, ...counter.buffer.asUint8List()];
      var u = hmac.convert(blockInput).bytes;
      var block = List<int>.from(u);
      for (var iteration = 1; iteration < iterations; iteration++) {
        u = hmac.convert(u).bytes;
        for (var index = 0; index < block.length; index++) {
          block[index] ^= u[index];
        }
      }
      result.addAll(block);
    }
    return Uint8List.fromList(result.take(length).toList());
  }

  Future<({String table, String name, String phone, String? count})?> _findSchema(Database db) async {
    final tables = await db.rawQuery(
      "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
    );
    for (final row in tables) {
      final table = row['name'] as String;
      final columns = await db.rawQuery('PRAGMA table_info(${_quote(table)})');
      final names = columns.map((column) => column['name'] as String).toList();
      final name = names.where((value) => value.toLowerCase() == 'an' || value.toLowerCase() == 'name').firstOrNull;
      final phone = names.where((value) => value.toLowerCase() == 'ap' || value.toLowerCase() == 'phone').firstOrNull;
      final count = names.where((value) => ['countt', 'count', 'occurrences'].contains(value.toLowerCase())).firstOrNull;
      if (name != null && phone != null) {
        return (table: table, name: name, phone: phone, count: count);
      }
    }
    return null;
  }

  Future<void> _openDatabase(File file, {required bool isBundled}) async {
    final db = await openDatabase(file.path, readOnly: true);
    final schema = await _findSchema(db);
    if (schema == null) {
      await db.close();
      return;
    }
    final table = schema.table;
    final rowCount = Sqflite.firstIntValue(await db.rawQuery('SELECT COUNT(*) FROM ${_quote(table)}')) ?? 0;
    final size = await file.length() / (1024 * 1024);
    final info = DatabaseInfo(
      fileName: p.basename(file.path),
      displayName: p.basenameWithoutExtension(file.path).replaceAll('_', ' '),
      tableName: table,
      recordCount: rowCount,
      sizeMb: size,
      isBundled: isBundled,
    );
    _databases.add(_DatabaseHandle(
      info: info,
      db: db,
      nameColumn: schema.name,
      phoneColumn: schema.phone,
      countColumn: schema.count,
    ));
  }

  Future<List<ContactRecord>> search(String query, {required bool byName, required NameSearchMode mode, int? limit}) async {
    await initialize();
    final term = query.trim();
    if (term.isEmpty) {
      if (limit == null) return <ContactRecord>[];
      return sample(limit);
    }
    final records = <ContactRecord>[];
    for (final handle in _databases) {
      final table = _quote(handle.info.tableName);
      final name = _quote(handle.nameColumn);
      final phone = _quote(handle.phoneColumn);
      final count = handle.countColumn == null ? '1' : _quote(handle.countColumn!);
      final args = <Object?>[];
      String where;
      if (!byName) {
        where = '$phone LIKE ?';
        args.add('%$term%');
      } else {
        final plainPredicates = _predicates(name, term, mode, args);
        where = plainPredicates;
        if (handle.info.isBundled) {
          final encodedArgs = <Object?>[];
          final encodedPredicates = _predicates(name, term, mode, encodedArgs, encode: true);
          where = '($plainPredicates) OR ($encodedPredicates)';
          args.addAll(encodedArgs);
        }
      }
      final rows = await handle.db.rawQuery(
        'SELECT $name AS _name, $phone AS _phone, $count AS _count FROM $table WHERE $where',
        args,
      );
      for (final row in rows) {
        final stored = row['_name']?.toString() ?? '';
        records.add(ContactRecord(
          name: handle.info.isBundled ? NameCodec.decodeIfObfuscated(stored) : stored,
          phone: row['_phone']?.toString() ?? '',
          count: (row['_count'] as num?)?.toInt() ?? 1,
          source: handle.info.displayName,
        ));
      }
    }

    if (!byName) {
      records.sort((a, b) => b.count.compareTo(a.count));
      return limit == null ? records : records.take(limit).toList();
    }
    final filtered = records.where((record) => ArabicSearch.matches(record.name, term, mode)).toList();
    if (mode == NameSearchMode.smart) {
      filtered.sort((a, b) => ArabicSearch.score(b.name, term).compareTo(ArabicSearch.score(a.name, term)));
    } else {
      filtered.sort((a, b) => b.count.compareTo(a.count));
    }
    return limit == null ? filtered : filtered.take(limit).toList();
  }

  String _predicates(String column, String term, NameSearchMode mode, List<Object?> args, {bool encode = false}) {
    String pattern(String value) => encode ? NameCodec.encodePattern(value) : value;
    final words = term.split(RegExp(r'\s+')).where((word) => word.isNotEmpty).toList();
    switch (mode) {
      case NameSearchMode.exact:
        args.addAll([pattern(term), pattern(term), pattern(term)]);
        return '$column = ? OR TRIM($column) = ? OR $column LIKE ?';
      case NameSearchMode.starts:
        args.addAll(['${pattern(term)}%', '${pattern(term)}%']);
        return '$column LIKE ? OR TRIM($column) LIKE ?';
      case NameSearchMode.ends:
        args.addAll(['%${pattern(term)}', '%${pattern(term)}']);
        return '$column LIKE ? OR TRIM($column) LIKE ?';
      case NameSearchMode.contains:
        args.add('%${pattern(term)}%');
        return '$column LIKE ?';
      case NameSearchMode.exactWord:
        if (words.length < 2) {
          args.add('%${pattern(term)}%');
          return '$column LIKE ?';
        }
        args.addAll(words.map((word) => '%${pattern(word)}%'));
        return words.map((_) => '$column LIKE ?').join(' AND ');
      case NameSearchMode.smart:
        if (words.length < 2) {
          args.add('%${pattern(term)}%');
          return '$column LIKE ?';
        }
        args.addAll(words.map((word) => '%${pattern(word)}%'));
        return words.map((_) => '$column LIKE ?').join(' OR ');
    }
  }

  Future<List<ContactRecord>> sample(int limit) async {
    await initialize();
    final result = <ContactRecord>[];
    final perDatabase = math.max(10, limit ~/ math.max(1, _databases.length));
    for (final handle in _databases) {
      final name = _quote(handle.nameColumn);
      final phone = _quote(handle.phoneColumn);
      final count = handle.countColumn == null ? '1' : _quote(handle.countColumn!);
      final rows = await handle.db.rawQuery(
        'SELECT $name AS _name, $phone AS _phone, $count AS _count FROM ${_quote(handle.info.tableName)} LIMIT ?',
        [perDatabase],
      );
      result.addAll(rows.map((row) {
        final stored = row['_name']?.toString() ?? '';
        return ContactRecord(
          name: handle.info.isBundled ? NameCodec.decodeIfObfuscated(stored) : stored,
          phone: row['_phone']?.toString() ?? '',
          count: (row['_count'] as num?)?.toInt() ?? 1,
          source: handle.info.displayName,
        );
      }));
    }
    return result.take(limit).toList();
  }

  Future<bool> importDatabase(String sourcePath) async {
    await initialize();
    final bytes = await File(sourcePath).readAsBytes();
    final directory = await getApplicationDocumentsDirectory();
    final filename = p.basename(sourcePath).toLowerCase().endsWith('.db')
        ? p.basename(sourcePath)
        : '${p.basename(sourcePath)}.db';
    final safeName = filename == _bundledFilename ? 'imported_${DateTime.now().millisecondsSinceEpoch}_$filename' : filename;
    final target = File(p.join(directory.path, 'contacts_dbs', safeName));
    final temp = File('${target.path}.tmp');
    await temp.writeAsBytes(bytes, flush: true);
    final validation = await openDatabase(temp.path, readOnly: true);
    final valid = await _findSchema(validation) != null;
    await validation.close();
    if (!valid) {
      await temp.delete();
      return false;
    }
    if (await target.exists()) await target.delete();
    await temp.rename(target.path);
    await _openDatabase(target, isBundled: false);
    return true;
  }

  Future<bool> deleteDatabase(String filename) async {
    await initialize();
    if (filename == _bundledFilename) return false;
    final index = _databases.indexWhere((item) => item.info.fileName == filename);
    if (index < 0) return false;
    final entry = _databases.removeAt(index);
    await entry.db.close();
    final directory = await getApplicationDocumentsDirectory();
    final file = File(p.join(directory.path, 'contacts_dbs', filename));
    if (await file.exists()) await file.delete();
    return true;
  }

  Future<void> clearImportedDatabases() async {
    await initialize();
    final imported = _databases.where((item) => !item.info.isBundled).toList();
    for (final entry in imported) {
      await deleteDatabase(entry.info.fileName);
    }
  }

  Future<void> createDemoDatabase() async {
    await initialize();
    final directory = await getApplicationDocumentsDirectory();
    final file = File(p.join(directory.path, 'contacts_dbs', 'Aden_Sample_Contacts.db'));
    if (await file.exists()) await file.delete();
    final db = await openDatabase(file.path, version: 1, onCreate: (database, version) async {
      await database.execute('CREATE TABLE callers (AN TEXT, AP TEXT, countt INTEGER)');
      final samples = [
        ['صالح ناصر اليافعي', '777123456', 12],
        ['محمد عبد الله باوزير', '733987654', 8],
        ['أروى علي حسين عوض', '711223344', 4],
        ['فاطمة صالح الكعبي', '700554433', 2],
        ['معاذ حسن الحريبي', '770112233', 15],
      ];
      final batch = database.batch();
      for (final record in samples) {
        batch.insert('callers', {'AN': record[0], 'AP': record[1], 'countt': record[2]});
      }
      await batch.commit(noResult: true);
    });
    await db.close();
    await _openDatabase(file, isBundled: false);
  }
}

String _quote(String identifier) => '"${identifier.replaceAll('"', '""')}"';

class NameCodec {
  static final Map<String, String> _encode = {
    for (var index = 0; index < _arabicLetters.length; index++)
      _arabicLetters[index]: _latinLetters[index],
  };
  static final Map<String, String> _decode = {
    for (var index = 0; index < _latinLetters.length; index++)
      _latinLetters[index]: _arabicLetters[index],
  };

  static String encodePattern(String value) => value.runes
      .map((rune) => _encode[String.fromCharCode(rune)] ?? String.fromCharCode(rune))
      .join();

  static String decodeIfObfuscated(String value) {
    final containsArabic = RegExp(r'[\u0600-\u06ff]').hasMatch(value);
    final latinLetters = RegExp(r'[A-Za-z]').allMatches(value).map((match) => match.group(0)!).toList();
    if (containsArabic || latinLetters.isEmpty || latinLetters.any((letter) => !_decode.containsKey(letter))) {
      return value;
    }
    return value.runes
        .map((rune) => _decode[String.fromCharCode(rune)] ?? String.fromCharCode(rune))
        .join();
  }
}

String _normalizeArabic(String value) => value
    .replaceAll(RegExp(r'[\u064b-\u065f\u0670]'), '')
    .replaceAll('\u0640', '')
    .replaceAll(RegExp('[إأآٱ]'), 'ا')
    .replaceAll('ى', 'ي')
    .replaceAll(RegExp(r'\s+'), ' ')
    .trim();

class ArabicSearch {
  static bool matches(String name, String query, NameSearchMode mode) {
    final normalizedName = _normalizeArabic(name);
    final normalizedQuery = _normalizeArabic(query);
    switch (mode) {
      case NameSearchMode.exact:
        return normalizedName == normalizedQuery;
      case NameSearchMode.starts:
        return normalizedName.startsWith(normalizedQuery);
      case NameSearchMode.ends:
        return normalizedName.endsWith(normalizedQuery);
      case NameSearchMode.contains:
        return normalizedName.contains(normalizedQuery);
      case NameSearchMode.exactWord:
        final nameWords = normalizedName.split(RegExp(r'[\s.,!?،؛؟:;()\-]+'));
        return normalizedQuery.split(RegExp(r'\s+')).every(nameWords.contains);
      case NameSearchMode.smart:
        return score(name, query) > 0;
    }
  }

  static int score(String name, String query) {
    final normalizedName = _normalizeArabic(name);
    final normalizedQuery = _normalizeArabic(query);
    final queryWords = normalizedQuery.split(RegExp(r'\s+')).where((word) => word.isNotEmpty).toList();
    final nameWords = normalizedName.split(RegExp(r'[\s.,!?،؛؟:;()\-]+')).where((word) => word.isNotEmpty).toList();
    if (queryWords.isEmpty) return 0;
    if (normalizedName == normalizedQuery) return 10000;
    final exactCount = queryWords.where(nameWords.contains).length;
    if (exactCount == queryWords.length) {
      return normalizedName.contains(normalizedQuery) ? 8500 : 6500;
    }
    if (exactCount > 0) return 3000 + exactCount * 1000 - nameWords.length * 10;
    final partial = queryWords.where((word) => nameWords.any((candidate) => candidate.startsWith(word))).length;
    return partial == queryWords.length ? 2000 : 0;
  }
}

class ContactsHomePage extends StatefulWidget {
  const ContactsHomePage({super.key});

  @override
  State<ContactsHomePage> createState() => _ContactsHomePageState();
}

class _ContactsHomePageState extends State<ContactsHomePage> {
  final _store = ContactStore.instance;
  final _queryController = TextEditingController();
  Timer? _debounce;
  List<ContactRecord> _results = [];
  NameSearchMode _mode = NameSearchMode.contains;
  bool _byName = true;
  bool _loading = true;
  bool _searching = false;
  bool _managerExpanded = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _queryController.addListener(_onQueryChanged);
    _loadStore();
  }

  @override
  void dispose() {
    _debounce?.cancel();
    _queryController.dispose();
    super.dispose();
  }

  Future<void> _loadStore() async {
    setState(() { _loading = true; _error = null; });
    try {
      await _store.initialize();
      if (mounted) setState(() { _loading = false; });
    } catch (error) {
      if (mounted) setState(() { _loading = false; _error = error.toString(); });
    }
  }

  void _onQueryChanged() {
    _debounce?.cancel();
    final query = _queryController.text.trim();
    if (query.isEmpty) {
      setState(() => _results = []);
      return;
    }
    _debounce = Timer(const Duration(milliseconds: 300), _search);
  }

  Future<void> _search() async {
    final term = _queryController.text.trim();
    if (term.isEmpty) return;
    setState(() => _searching = true);
    try {
      final results = await _store.search(term, byName: _byName, mode: _mode);
      if (mounted) setState(() { _results = results; _searching = false; });
    } catch (error) {
      if (mounted) setState(() { _searching = false; _error = error.toString(); });
    }
  }

  Future<void> _showMessage(String message) async {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(message)));
  }

  Future<void> _importDatabase() async {
    final file = await FilePicker.platform.pickFiles(type: FileType.custom, allowedExtensions: ['db', 'db3', 'sqlite']);
    final path = file?.files.single.path;
    if (path == null) return;
    setState(() => _loading = true);
    try {
      final imported = await _store.importDatabase(path);
      if (!imported) {
        await _showMessage('تعذر استيراد الملف: لا يوجد جدول يحتوي الاسم ورقم الهاتف.');
      } else {
        await _showMessage('تم استيراد قاعدة البيانات.');
      }
    } catch (error) {
      await _showMessage('فشل الاستيراد: $error');
    }
    if (mounted) setState(() => _loading = false);
  }

  Future<void> _showDatabaseManager() async {
    setState(() => _managerExpanded = !_managerExpanded);
  }

  Future<void> _deleteDatabase(DatabaseInfo info) async {
    if (info.isBundled) {
      await _showMessage('قاعدة البيانات الأساسية لا يمكن حذفها.');
      return;
    }
    await _store.deleteDatabase(info.fileName);
    if (mounted) setState(() {});
  }

  Future<void> _clearImported() async {
    await _store.clearImportedDatabases();
    if (mounted) setState(() { _managerExpanded = false; });
    await _showMessage('تم حذف قواعد البيانات المستوردة.');
  }

  Future<void> _createDemo() async {
    await _store.createDemoDatabase();
    if (mounted) setState(() {});
    await _showMessage('تم إنشاء قاعدة بيانات تجريبية.');
  }

  @override
  Widget build(BuildContext context) {
    final infos = _store.infos;
    final totalRecords = infos.fold<int>(0, (total, info) => total + info.recordCount);
    final totalSize = infos.fold<double>(0, (total, info) => total + info.sizeMb);
    return Scaffold(
      body: SafeArea(
        child: _loading && infos.isEmpty
            ? const Center(child: CircularProgressIndicator())
            : CustomScrollView(
                slivers: [
                  SliverPadding(
                    padding: const EdgeInsets.fromLTRB(16, 12, 16, 20),
                    sliver: SliverList.list(children: [
                      _buildHeader(infos, totalRecords, totalSize),
                      const SizedBox(height: 14),
                      if (_error != null) _buildError(),
                      if (!_store.isReady) _buildEmptyState() else ...[
                        _buildSearchControls(),
                        const SizedBox(height: 18),
                        _buildResultHeading(),
                      ],
                    ]),
                  ),
                  if (_store.isReady && _results.isNotEmpty)
                    SliverPadding(
                      padding: const EdgeInsets.fromLTRB(16, 0, 16, 24),
                      sliver: SliverList.separated(
                        itemCount: _results.length,
                        separatorBuilder: (_, __) => const SizedBox(height: 8),
                        itemBuilder: (context, index) => _contactTile(_results[index]),
                      ),
                    ),
                ],
              ),
      ),
      floatingActionButton: _store.isReady
          ? FloatingActionButton.small(
              tooltip: 'استيراد قاعدة',
              onPressed: _loading ? null : _importDatabase,
              child: const Icon(Icons.add),
            )
          : null,
    );
  }

  Widget _buildHeader(List<DatabaseInfo> infos, int totalRecords, double totalSize) {
    return Container(
      padding: const EdgeInsets.fromLTRB(18, 18, 14, 16),
      decoration: BoxDecoration(
        color: const Color(0xFFE4EFEB),
        borderRadius: BorderRadius.circular(8),
        border: const Border(right: BorderSide(color: Color(0xFF137C78), width: 4)),
      ),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Row(children: [
          Container(
            width: 42,
            height: 42,
            decoration: BoxDecoration(color: const Color(0xFF137C78), borderRadius: BorderRadius.circular(8)),
            child: const Icon(Icons.call, color: Colors.white),
          ),
          const SizedBox(width: 12),
          const Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text('كاشف أرقام عدن', style: TextStyle(fontSize: 20, fontWeight: FontWeight.w800, color: Color(0xFF17252A))),
            SizedBox(height: 3),
            Text('بحث محلي دون اتصال', style: TextStyle(fontSize: 13, color: Color(0xFF526763))),
          ])),
          IconButton(
            tooltip: 'إدارة قواعد البيانات',
            onPressed: _showDatabaseManager,
            icon: Icon(_managerExpanded ? Icons.close : Icons.storage_outlined),
          ),
        ]),
        if (infos.isNotEmpty) ...[
          const Divider(height: 24),
          Wrap(spacing: 10, runSpacing: 8, children: [
            _statChip(Icons.storage, '${infos.length} قاعدة'),
            _statChip(Icons.contacts, '$totalRecords سجل'),
            _statChip(Icons.sd_storage_outlined, '${totalSize.toStringAsFixed(1)} MB'),
          ]),
        ],
        if (_managerExpanded) ...[
          const Divider(height: 24),
          Row(children: [
            const Expanded(child: Text('قواعد البيانات', style: TextStyle(fontWeight: FontWeight.bold))),
            TextButton.icon(onPressed: _clearImported, icon: const Icon(Icons.delete_outline, size: 18), label: const Text('حذف المستوردة')),
          ]),
          for (final info in infos) _databaseRow(info),
        ],
      ]),
    );
  }

  Widget _statChip(IconData icon, String label) => Container(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
        decoration: BoxDecoration(color: Colors.white.withOpacity(0.72), borderRadius: BorderRadius.circular(6)),
        child: Row(mainAxisSize: MainAxisSize.min, children: [Icon(icon, size: 15, color: const Color(0xFF137C78)), const SizedBox(width: 6), Text(label, style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w600))]),
      );

  Widget _databaseRow(DatabaseInfo info) => Padding(
        padding: const EdgeInsets.only(top: 8),
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
          decoration: BoxDecoration(color: Colors.white, borderRadius: BorderRadius.circular(6)),
          child: Row(children: [
            Icon(info.isBundled ? Icons.offline_bolt : Icons.folder_open, color: const Color(0xFF137C78), size: 19),
            const SizedBox(width: 8),
            Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text(info.displayName, maxLines: 1, overflow: TextOverflow.ellipsis, style: const TextStyle(fontWeight: FontWeight.w700)),
              Text('${info.recordCount} سجل · ${info.sizeMb.toStringAsFixed(1)} MB', style: const TextStyle(fontSize: 12, color: Color(0xFF66736F))),
            ])),
            if (!info.isBundled) IconButton(tooltip: 'حذف القاعدة', onPressed: () => _deleteDatabase(info), icon: const Icon(Icons.delete_outline, color: Color(0xFFB44D42))),
          ]),
        ),
      );

  Widget _buildSearchControls() => Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        SegmentedButton<bool>(
          segments: const [
            ButtonSegment(value: true, icon: Icon(Icons.person_outline), label: Text('الاسم')),
            ButtonSegment(value: false, icon: Icon(Icons.phone_outlined), label: Text('الرقم')),
          ],
          selected: {_byName},
          onSelectionChanged: (value) {
            setState(() => _byName = value.first);
            if (_queryController.text.isNotEmpty) _search();
          },
        ),
        if (_byName) ...[
          const SizedBox(height: 14),
          DropdownButtonFormField<NameSearchMode>(
            value: _mode,
            decoration: const InputDecoration(labelText: 'طريقة البحث', prefixIcon: Icon(Icons.tune)),
            items: NameSearchMode.values.map((mode) => DropdownMenuItem(
              value: mode,
              child: Row(children: [Icon(mode.icon, size: 18), const SizedBox(width: 10), Text(mode.label)]),
            )).toList(),
            onChanged: (mode) {
              if (mode == null) return;
              setState(() => _mode = mode);
              if (_queryController.text.isNotEmpty) _search();
            },
          ),
        ],
        const SizedBox(height: 12),
        TextField(
          controller: _queryController,
          keyboardType: _byName ? TextInputType.text : TextInputType.phone,
          textInputAction: TextInputAction.search,
          onSubmitted: (_) => _search(),
          decoration: InputDecoration(
            labelText: _byName ? 'اسم الشخص' : 'رقم الهاتف',
            hintText: _byName ? 'اكتب الاسم للبحث' : 'أدخل رقم الهاتف أو جزءًا منه',
            prefixIcon: Icon(_byName ? Icons.person_search_outlined : Icons.phone),
            suffixIcon: _searching
                ? const Padding(padding: EdgeInsets.all(14), child: SizedBox(width: 18, height: 18, child: CircularProgressIndicator(strokeWidth: 2)))
                : IconButton(tooltip: 'مسح البحث', onPressed: _queryController.clear, icon: const Icon(Icons.clear)),
          ),
        ),
        const SizedBox(height: 10),
        SizedBox(
          width: double.infinity,
          child: FilledButton.icon(
            onPressed: _searching ? null : _search,
            icon: const Icon(Icons.search),
            label: const Text('بحث في السجلات'),
          ),
        ),
      ]);

  Widget _buildResultHeading() {
    final query = _queryController.text.trim();
    if (query.isEmpty) {
      return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        const Text('ابحث في دليل الأرقام', style: TextStyle(fontSize: 17, fontWeight: FontWeight.w800)),
        const SizedBox(height: 5),
        const Text('تعمل قاعدة البيانات محليًا على جهازك.', style: TextStyle(color: Color(0xFF66736F))),
        const SizedBox(height: 14),
        OutlinedButton.icon(
          onPressed: () async { setState(() => _searching = true); final rows = await _store.sample(100); if (mounted) setState(() { _results = rows; _searching = false; }); },
          icon: const Icon(Icons.list_alt),
          label: const Text('عرض عينة من 100 سجل'),
        ),
        if (_results.isNotEmpty) Padding(padding: const EdgeInsets.only(top: 18), child: Text('عينة أولية (${_results.length})', style: const TextStyle(fontWeight: FontWeight.w800))),
      ]);
    }
    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: Text('النتائج: ${_results.length}', style: const TextStyle(fontSize: 17, fontWeight: FontWeight.w800)),
    );
  }

  Widget _contactTile(ContactRecord record) {
    final carrier = _carrierName(record.phone);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
      decoration: BoxDecoration(color: const Color(0xFFFFFEFA), borderRadius: BorderRadius.circular(8), border: Border.all(color: const Color(0xFFE1E6E1))),
      child: Row(children: [
        Container(
          width: 40,
          height: 40,
          decoration: BoxDecoration(color: const Color(0xFFE4EFEB), borderRadius: BorderRadius.circular(7)),
          child: const Icon(Icons.person_outline, color: Color(0xFF137C78)),
        ),
        const SizedBox(width: 12),
        Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(record.name.isEmpty ? 'اسم غير متوفر' : record.name, maxLines: 2, overflow: TextOverflow.ellipsis, style: const TextStyle(fontWeight: FontWeight.w800)),
          const SizedBox(height: 4),
          Text(record.phone, textDirection: TextDirection.ltr, style: const TextStyle(fontFeatures: [FontFeature.tabularFigures()], fontWeight: FontWeight.w700, color: Color(0xFF137C78))),
          if (carrier != null) Text(carrier, style: const TextStyle(fontSize: 11, color: Color(0xFF66736F))),
        ])),
        IconButton(
          tooltip: 'نسخ رقم الهاتف',
          onPressed: () async { await Clipboard.setData(ClipboardData(text: record.phone)); await _showMessage('تم نسخ الرقم.'); },
          icon: const Icon(Icons.copy_outlined, size: 19),
        ),
      ]),
    );
  }

  Widget _buildEmptyState() => Container(
        margin: const EdgeInsets.only(top: 24),
        padding: const EdgeInsets.all(20),
        decoration: BoxDecoration(color: Colors.white, borderRadius: BorderRadius.circular(8), border: Border.all(color: const Color(0xFFE1E6E1))),
        child: Column(children: [
          const Icon(Icons.storage_outlined, size: 42, color: Color(0xFF137C78)),
          const SizedBox(height: 10),
          const Text('لا توجد قاعدة بيانات قابلة للفتح', style: TextStyle(fontWeight: FontWeight.w800, fontSize: 16)),
          if (_error != null) Padding(padding: const EdgeInsets.only(top: 8), child: Text(_error!, textAlign: TextAlign.center, style: const TextStyle(color: Color(0xFFB44D42)))),
          const SizedBox(height: 12),
          FilledButton.icon(onPressed: _importDatabase, icon: const Icon(Icons.upload_file), label: const Text('استيراد قاعدة بيانات')),
          TextButton.icon(onPressed: _createDemo, icon: const Icon(Icons.science_outlined), label: const Text('إنشاء قاعدة تجريبية')),
        ]),
      );

  Widget _buildError() => Container(
        margin: const EdgeInsets.only(bottom: 14),
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(color: const Color(0xFFFFE9E2), borderRadius: BorderRadius.circular(8)),
        child: Text(_error!, style: const TextStyle(color: Color(0xFF8A342D))),
      );
}

String? _carrierName(String phone) {
  final clean = phone.replaceAll(RegExp(r'\D'), '');
  if (clean.length < 3) return null;
  final prefix = clean.length >= 3 ? clean.substring(0, 3) : clean;
  if (['770', '771', '773', '774', '780', '781', '783', '784'].contains(prefix)) return 'يمن موبايل';
  if (['710', '711', '712', '713', '714', '715', '716', '717', '718'].contains(prefix)) return 'YOU';
  if (['730', '731', '732', '733', '734', '735', '736', '737', '738'].contains(prefix)) return 'سبأفون';
  if (['700', '701', '702', '703', '704', '705'].contains(prefix)) return 'واي';
  return null;
}
