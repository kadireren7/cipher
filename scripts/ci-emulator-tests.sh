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
IMG="system-images;android-34;google_apis;x86_64"
# Downloads from dl.google.com are occasionally truncated ("Error on ZipFile unknown archive"): retry, and require the image to really be on disk.
for attempt in 1 2 3 4; do
  rm -rf "$SDK/system-images/android-34" # never reuse a half-extracted image
  if "$SDK/cmdline-tools/latest/bin/sdkmanager" "platform-tools" "emulator" "platforms;android-36" "build-tools;36.0.0" "ndk;27.2.12479018" "$IMG" 2>&1 | tail -n 5 \
     && [ -s "$SDK/system-images/android-34/google_apis/x86_64/system.img" ]; then break; fi
  echo "sdkmanager attempt $attempt did not produce a complete image" >&2
  [ "$attempt" = 4 ] && { echo "system image could not be installed" >&2; exit 1; }
  sleep 20
done
ls "$SDK/system-images/android-34/google_apis/x86_64" >/dev/null # fail loudly if the image was not installed
mkdir -p "$HOME/.android/avd"
export ANDROID_AVD_HOME="$HOME/.android/avd"
echo no | "$SDK/cmdline-tools/latest/bin/avdmanager" --verbose create avd -n ci34 -k "system-images;android-34;google_apis;x86_64" -d pixel_5 --force || echo "avdmanager exit code $?" >&2
echo "--- avdmanager list avd"; "$SDK/cmdline-tools/latest/bin/avdmanager" list avd || true
echo "--- $ANDROID_AVD_HOME"; ls -la "$ANDROID_AVD_HOME" || true
"$SDK/emulator/emulator" -list-avds | grep -qx ci34 || { echo "AVD ci34 was not created" >&2; exit 1; }
"$SDK/emulator/emulator" -avd ci34 -no-window -no-audio -no-boot-anim -gpu swiftshader_indirect -no-snapshot &
EMU=$!
# Bounded waits: a missing or crashed emulator must fail the job, not hang it.
timeout 300 "$SDK/platform-tools/adb" wait-for-device || { echo "emulator did not appear" >&2; exit 1; }
for _ in $(seq 1 120); do
  kill -0 "$EMU" 2>/dev/null || { echo "emulator exited" >&2; exit 1; }
  [ "$("$SDK/platform-tools/adb" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ] && break
  sleep 5
done
[ "$("$SDK/platform-tools/adb" shell getprop sys.boot_completed | tr -d '\r')" = "1" ] || { echo "emulator boot timed out" >&2; exit 1; }
# Adversarial TLS servers for the network-attack tests (they are skipped when these are not running).
bash scripts/make-test-ca.sh
python3 -m pip install --quiet cryptography
python3 scripts/adversarial-tls-servers.py &
sleep 3
trap '"$SDK/platform-tools/adb" logcat -d > /tmp/emulator-logcat.txt 2>&1 || true' EXIT
if [ "${CIPHER_E2E:-}" = "multirelay" ]; then
  # Two independent relays + the real app on the emulator + a headless peer; every phase must pass (the driver exits non-zero otherwise).
  cargo build --release --locked -p cipher-relay -p cipher-ffi --example e2e_peer
  (cd android && ./gradlew --no-daemon :app:assembleDebug :app:assembleDebugAndroidTest)
  timeout 1500 python3 -u scripts/android-e2e-multirelay.py 2>&1 | tee /tmp/e2e-multirelay.txt
  exit "${PIPESTATUS[0]}"
fi
(cd android && ./gradlew --no-daemon :app:connectedDebugAndroidTest)
