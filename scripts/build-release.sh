#!/bin/bash
# Build release APK and upload to GitHub Releases
set -euo pipefail
cd "$(dirname "$0")/.."

npm install
npx cap add android 2>/dev/null || true
npx cap sync android

# Build release APK (signable)
cd android
./gradlew assembleRelease
cd ..

APK="android/app/build/outputs/apk/release/app-release-unsigned.apk"
if [ -f "$APK" ]; then
    echo "✅ Release APK built: $APK"
    ls -lh "$APK"
else
    echo "❌ Build failed"
    exit 1
fi
