# Aden Phone Detector (Flutter)

This folder contains the Flutter implementation of the Android contact lookup app. The original Kotlin project remains in the parent `phone` directory until this Flutter version can be generated and built with an installed Flutter SDK.

## Features

- Arabic RTL interface, name and phone search, and six name-search modes.
- Offline SQLite lookup, database import, record samples, and database management.
- First-run AES/PBKDF2 decryption and ZIP extraction of the bundled database asset.
- Accepts both `AN`/`AP` and `name`/`phone` SQLite schemas.
- Preserves Arabic names and decodes Latin-only names that match the provided substitution alphabet.

## Run on Windows

Install Flutter and Android SDK Platform 34, then run these commands from this directory:

```powershell
flutter create --platforms=android .
flutter pub get
flutter test
flutter run
```

To build a debug APK:

```powershell
flutter build apk --debug
```

The APK is written to `build\app\outputs\flutter-apk\app-debug.apk`.