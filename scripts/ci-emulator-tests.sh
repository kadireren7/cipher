#!/usr/bin/env bash
# Boots a headless API 34 x86_64 emulator and runs the instrumented tests. Used by CI; also usable locally.
# Honest scope: an emulator Keystore is software-backed, so this does NOT test hardware, biometrics or StrongBox.
set -euo pipefail
cd "$(dirname "$0")/.."
SDK="${ANDROID_HOME:-$HOME/android-sdk}"
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$SDK/ndk/27.2.12479018}"
rustup target add aarch64-linux-android x86_64-linux-android
command -v cargo-ndk >/dev/null || cargo install --locked cargo-ndk@3.5.4
yes | "$SDK/cmdline-tools/latest/bin/sdkmanager" --licenses >/dev/null || true
"$SDK/cmdline-tools/latest/bin/sdkmanager" "platform-tools" "emulator" "platforms;android-36" "build-tools;36.0.0" "ndk;27.2.12479018" "system-images;android-34;google_apis;x86_64" >/dev/null
echo no | "$SDK/cmdline-tools/latest/bin/avdmanager" create avd -n ci34 -k "system-images;android-34;google_apis;x86_64" --force
"$SDK/emulator/emulator" -avd ci34 -no-window -no-audio -no-boot-anim -gpu swiftshader_indirect -no-snapshot &
"$SDK/platform-tools/adb" wait-for-device
until [ "$("$SDK/platform-tools/adb" shell getprop sys.boot_completed | tr -d '\r')" = "1" ]; do sleep 5; done
# Adversarial TLS servers for the network-attack tests (they are skipped when these are not running).
bash scripts/make-test-ca.sh
python3 -m pip install --quiet cryptography
python3 scripts/adversarial-tls-servers.py &
sleep 3
(cd android && ./gradlew --no-daemon :app:connectedDebugAndroidTest)
