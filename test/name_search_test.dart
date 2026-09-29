import 'package:aden_phone_detector/main.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('substitution map round trips every supported Arabic letter', () {
    const arabic = 'ابتثجحخدذرزسشصضطظعغفقكلمنهويى';
    const latin = 'tvjHKdorszxSDTZugfqklmnhwyYpa';

    expect(NameCodec.encodePattern(arabic), latin);
    expect(NameCodec.decodeIfObfuscated(latin), arabic);
  });

  test('plain Arabic names are not altered by obfuscation decoding', () {
    expect(NameCodec.decodeIfObfuscated('أحمد محمد'), 'أحمد محمد');
    expect(NameCodec.decodeIfObfuscated('tvj-123'), 'ابت-123');
  });

  test('Arabic matching normalizes alef, tashkeel, and spaces', () {
    expect(ArabicSearch.matches('  أَحمد   محمد ', 'احمد محمد', NameSearchMode.exact), isTrue);
    expect(ArabicSearch.matches('محمد علي', 'علي', NameSearchMode.exactWord), isTrue);
    expect(ArabicSearch.matches('علياء محمد', 'علي', NameSearchMode.exactWord), isFalse);
  });

  test('smart search rejects unrelated names', () {
    expect(ArabicSearch.score('عبدالله حسن', 'محمد علي'), 0);
    expect(ArabicSearch.score('محمد علي أحمد', 'محمد علي'), greaterThan(0));
  });
}
