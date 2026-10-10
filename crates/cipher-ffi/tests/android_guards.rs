#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Static guards over the Android project: they fail the build if a hardening decision is weakened.
//!
//! These read the SOURCE (manifest, Gradle, Kotlin, resources). They are a regression net, not a proof: the installed package is
//! checked again by `android/app/src/androidTest/.../HardeningInstrumentedTest.kt` on a real emulator/device.
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../android")
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn kotlin_main() -> Vec<(String, String)> {
    fn walk(d: &Path, out: &mut Vec<PathBuf>) {
        for e in std::fs::read_dir(d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "kt") {
                out.push(p);
            }
        }
    }
    let base = root().join("app/src/main/java");
    let mut v = Vec::new();
    walk(&base, &mut v);
    v.into_iter().map(|p| (p.strip_prefix(&base).unwrap().display().to_string(), std::fs::read_to_string(&p).unwrap())).collect()
}

/// Code lines only: whole-line comments and KDoc continuation lines are not code.
fn code(src: &str) -> Vec<(usize, &str)> {
    src.lines()
        .enumerate()
        .filter(|(_, l)| {
            let t = l.trim_start();
            !(t.starts_with("//") || t.starts_with('*') || t.starts_with("/*"))
        })
        .map(|(i, l)| (i + 1, l))
        .collect()
}

fn hits<'a>(src: &'a str, needles: &[&str]) -> Vec<(usize, &'a str)> {
    code(src).into_iter().filter(|(_, l)| needles.iter().any(|n| l.contains(n))).collect()
}

#[test]
fn guard_detector_has_a_negative_control() {
    let bad = "val x = WebView(ctx)\n// WebView in a comment is fine\n * WebView in kdoc is fine\nAlertDialog(onDismissRequest = {})";
    assert_eq!(hits(bad, &["WebView"]).len(), 1);
    assert_eq!(hits(bad, &["AlertDialog("]).len(), 1);
    assert!(!kotlin_main().is_empty(), "guards must read the real Kotlin sources");
}

#[test]
fn manifest_is_locked_down() {
    let m = read("app/src/main/AndroidManifest.xml");
    let m: String = m.lines().filter(|l| !l.trim_start().starts_with("<!--")).collect::<Vec<_>>().join("\n");
    assert!(m.contains(r#"android:allowBackup="false""#));
    assert!(m.contains(r#"android:usesCleartextTraffic="false""#));
    assert!(m.contains("android:networkSecurityConfig="));
    assert!(m.contains("android:dataExtractionRules="));
    assert!(!m.contains("android:debuggable"), "debuggable is decided by the build type only");
    assert!(!m.contains("requestLegacyExternalStorage"));
    assert!(!m.contains("<provider"), "no ContentProvider/FileProvider: nothing is shared with other apps");
    assert!(!m.contains("<service"), "no services declared");
    // The only `<receiver` allowed is a REMOVAL marker for a library-contributed exported receiver (tools:node="remove").
    for chunk in m.split("<receiver").skip(1) {
        let element = chunk.split("/>").next().unwrap_or("");
        assert!(element.contains(r#"tools:node="remove""#), "no receivers of our own: dynamic registration only");
    }
    assert!(m.contains(r#"android:name="androidx.profileinstaller.ProfileInstallReceiver""#) && m.contains(r#"tools:node="remove""#));
    assert!(!m.contains("android:scheme") && !m.contains("<data "), "no deep links");
    assert_eq!(m.matches("<activity").count(), 1, "exactly one activity");
    assert_eq!(m.matches("<intent-filter>").count(), 1, "only MAIN/LAUNCHER");
    assert!(m.contains("android.intent.action.MAIN") && m.contains("android.intent.category.LAUNCHER"));
    assert!(!m.contains("android.intent.action.VIEW") && !m.contains("android.intent.action.SEND"));
    for p in [
        "READ_CONTACTS",
        "WRITE_CONTACTS",
        "READ_EXTERNAL_STORAGE",
        "WRITE_EXTERNAL_STORAGE",
        "MANAGE_EXTERNAL_STORAGE",
        "READ_PHONE_STATE",
        "READ_SMS",
        "ACCESS_FINE_LOCATION",
        "ACCESS_COARSE_LOCATION",
        "SYSTEM_ALERT_WINDOW",
        "REQUEST_INSTALL_PACKAGES",
        "GET_ACCOUNTS",
        "QUERY_ALL_PACKAGES",
        "READ_MEDIA_",
    ] {
        assert!(!m.contains(p), "forbidden permission {p}");
    }
}

#[test]
fn every_activity_extends_secure_activity_and_nothing_clears_the_flag() {
    for (f, t) in kotlin_main() {
        for (n, l) in hits(&t, &[": ComponentActivity", ": AppCompatActivity", ": FragmentActivity", ": Activity("]) {
            assert!(f.ends_with("SecureActivity.kt"), "{f}:{n}: activities must extend SecureActivity, found `{}`", l.trim());
        }
        for (n, l) in
            hits(&t, &["clearFlags", "FLAG_SECURE) ", "setRecentsScreenshotEnabled(true)", "SecureOff", "SecureFlagPolicy.Inherit"])
        {
            assert!(
                !(l.contains("clearFlags")
                    || l.contains("SecureOff")
                    || l.contains("Inherit")
                    || l.contains("setRecentsScreenshotEnabled(true)")),
                "{f}:{n}: FLAG_SECURE must never be cleared or relaxed: `{}`",
                l.trim()
            );
        }
    }
    let sa = read("app/src/main/java/app/cipher/messenger/SecureActivity.kt");
    let flag = sa.find("FLAG_SECURE").expect("SecureActivity sets FLAG_SECURE");
    let create = sa.find("super.onCreate").expect("super.onCreate");
    assert!(flag < create, "FLAG_SECURE must be set BEFORE any content is created");
}

#[test]
fn dialogs_are_only_created_through_secure_dialog() {
    for (f, t) in kotlin_main() {
        for (n, l) in hits(&t, &["AlertDialog(", "Dialog(", "BasicAlertDialog(", "DropdownMenu(", "ModalBottomSheet("]) {
            let ok = f.ends_with("components/Components.kt") || l.contains("SecureDialog(");
            assert!(ok, "{f}:{n}: use SecureDialog (new windows do not inherit FLAG_SECURE): `{}`", l.trim());
        }
    }
    let c = read("app/src/main/java/app/cipher/messenger/ui/components/Components.kt");
    assert!(c.contains("SecureFlagPolicy.SecureOn"));
}

#[test]
fn banned_apis_do_not_appear_in_app_code() {
    let banned: &[&str] = &[
        "WebView",
        "addJavascriptInterface",
        "setJavaScriptEnabled",
        "X509TrustManager",
        "HostnameVerifier",
        "SSLSocketFactory",
        "sslSocketFactory(",
        "hostnameVerifier(",
        "trustAll",
        "ConnectionSpec.CLEARTEXT",
        "getSharedPreferences",
        "PreferenceManager",
        "DataStore",
        "MODE_WORLD",
        "getExternalFilesDir",
        "getExternalCacheDir",
        "Environment.getExternalStorage",
        "FileProvider",
        "Runtime.getRuntime",
        "ProcessBuilder",
        "System.setProperty",
        "printStackTrace",
        "println(",
        "Log.v(",
        "Log.d(",
        "Log.w(",
        "Log.e(",
        "Timber",
        "Crashlytics",
        "FirebaseAnalytics",
        "setPrimaryClip(ClipData.newPlainText(\"\"",
        "ACTION_VIEW",
        "ACTION_SEND",
        "startActivity(",
    ];
    for (f, t) in kotlin_main() {
        for (n, l) in hits(&t, banned) {
            // the one place allowed to touch the clipboard / the one logger / the one TLS trust component (certificate-pinned relays)
            let tls_api = ["X509TrustManager", "SSLSocketFactory", "sslSocketFactory("].iter().any(|b| l.contains(b));
            let allowed = (f.ends_with("SensitiveClipboard.kt"))
                || (f.ends_with("SafeLog.kt") && l.contains("Log.i("))
                || (tls_api
                    && (f.ends_with("net/PinnedTls.kt")
                        || (f.ends_with("net/OkHttpCallbacks.kt") && l.contains("sslSocketFactory(pinnedTls."))));
            assert!(allowed, "{f}:{n}: banned API: `{}`", l.trim());
        }
    }
}

#[test]
fn only_safelog_may_call_android_log_and_it_takes_closed_codes_only() {
    for (f, t) in kotlin_main() {
        if f.ends_with("SafeLog.kt") {
            assert!(t.contains("enum class Code"));
            assert!(!t.contains("fun event(msg: String") && !t.contains("fun event(code: Code, msg"), "SafeLog must not accept free text");
            continue;
        }
        if let Some((n, l)) = hits(&t, &["android.util.Log", "Log.i(", "Log.wtf("]).first() {
            panic!("{f}:{n}: only SafeLog may log: `{}`", l.trim());
        }
    }
}

#[test]
fn release_build_is_strict_and_the_debug_bypass_is_debug_only() {
    let g = read("app/build.gradle.kts");
    let release = &g[g.find("release {").expect("release block")..];
    let release = &release[..release.find("\n        }").expect("end of release block")];
    assert!(release.contains(r#""ALLOW_SOFTWARE_KEYSTORE", "false""#), "release must refuse software keystores");
    assert!(release.contains("isMinifyEnabled = true") && release.contains("isDebuggable = false"));
    assert!(release.contains(r#""DEFAULT_RELAY_URL", "\"\"""#), "no relay baked into release");
    assert!(!g.contains("google-services") && !g.contains("firebase"), "no Google/Firebase services");
    assert!(
        !g.contains("signingConfigs.getByName(\"debug\")") || !release.contains("getByName(\"debug\")"),
        "release is never debug-signed"
    );

    let host = read("app/src/main/java/app/cipher/messenger/data/EngineHost.kt");
    let lines: Vec<&str> = host
        .lines()
        .filter(|l| l.contains("debug_no_user_auth") && !l.trim_start().starts_with("//") && !l.trim_start().starts_with('*'))
        .collect();
    assert_eq!(lines.len(), 1, "exactly one use of the emulator-only bypass");
    assert!(lines[0].contains("BuildConfig.DEBUG &&"), "the bypass must be gated by BuildConfig.DEBUG: {}", lines[0]);
    for (f, t) in kotlin_main() {
        if !f.ends_with("EngineHost.kt") {
            assert!(!t.contains("debug_no_user_auth"), "{f}: bypass marker referenced outside EngineHost");
        }
    }
}

#[test]
fn network_security_config_is_system_trust_only_in_release() {
    let main = read("app/src/main/res/xml/network_security_config.xml");
    let nsc: String = main
        .lines()
        .filter(|l| !l.trim_start().starts_with("<!--") && !l.trim_start().starts_with("Certificate") && !l.trim_start().starts_with("ST-"))
        .collect();
    assert!(nsc.contains(r#"cleartextTrafficPermitted="false""#));
    assert!(!nsc.contains(r#"cleartextTrafficPermitted="true""#));
    assert!(!nsc.contains("debug-overrides"), "debug overrides must live in src/debug only");
    assert!(!nsc.contains(r#"src="user""#), "user-installed CAs are never trusted");
    assert!(nsc.contains(r#"src="system""#));

    let dbg = read("app/src/debug/res/xml/network_security_config.xml");
    assert!(dbg.contains("<debug-overrides>") && dbg.contains("@raw/test_ca"));
    assert!(!dbg.contains(r#"src="user""#) && !dbg.contains(r#"cleartextTrafficPermitted="true""#));

    let gi = std::fs::read_to_string(root().join("../.gitignore")).unwrap();
    assert!(gi.contains("android/app/src/debug/res/raw/"), "the throwaway test CA must never be committed");
}

#[test]
fn transport_is_tls13_only_with_no_redirects_and_no_custom_trust() {
    let t = read("app/src/main/java/app/cipher/messenger/net/OkHttpCallbacks.kt");
    assert!(t.contains("TlsVersion.TLS_1_3") && t.contains("connectionSpecs(listOf(tls13Only))"));
    assert!(!t.contains("TLS_1_2") && !t.contains("TLS_1_0") && !t.contains("CLEARTEXT"));
    assert!(t.contains("followRedirects(false)") && t.contains("followSslRedirects(false)"));
    assert!(t.contains(r#"require(base.startsWith("https://"))"#), "every request is refused unless https");
}

#[test]
fn backup_rules_exclude_everything() {
    let r = read("app/src/main/res/xml/data_extraction_rules.xml");
    for section in ["cloud-backup", "device-transfer"] {
        let s = &r[r.find(&format!("<{section}>")).unwrap()..r.find(&format!("</{section}>")).unwrap()];
        for d in ["root", "file", "database", "sharedpref", "external"] {
            assert!(s.contains(&format!(r#"<exclude domain="{d}" />"#)), "{section} must exclude {d}");
        }
        assert!(!s.contains("<include"), "{section}: nothing may be included");
    }
}

#[test]
fn r8_strips_android_logging_in_release() {
    let p = read("app/proguard-rules.pro");
    assert!(p.contains("-assumenosideeffects class android.util.Log"));
    for lvl in ["v", "d", "i", "w", "e", "wtf"] {
        assert!(p.contains(&format!("public static int {lvl}(...);")), "R8 must strip Log.{lvl}");
    }
}

#[test]
fn dependencies_contain_no_trackers_webviews_or_cloud_sdks() {
    let toml = read("gradle/libs.versions.toml").to_lowercase();
    let gradle = read("app/build.gradle.kts").to_lowercase();
    for bad in [
        "firebase",
        "crashlytics",
        "analytics",
        "play-services",
        "gms",
        "webkit",
        "admob",
        "facebook",
        "sentry",
        "bugsnag",
        "appsflyer",
        "mixpanel",
        "segment",
    ] {
        assert!(!toml.contains(bad) && !gradle.contains(bad), "dependency on `{bad}` is not allowed");
    }
}

#[test]
fn no_secrets_or_private_keys_are_committed_in_the_android_tree() {
    fn walk(d: &Path, out: &mut Vec<PathBuf>) {
        for e in std::fs::read_dir(d).unwrap().flatten() {
            let p = e.path();
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            if p.is_dir() {
                if !["build", ".gradle", ".idea"].contains(&name.as_str()) {
                    walk(&p, out);
                }
            } else {
                out.push(p);
            }
        }
    }
    let mut files = Vec::new();
    walk(&root(), &mut files);
    for f in files {
        let name = f.file_name().unwrap().to_string_lossy().to_string();
        assert!(
            !name.ends_with(".jks") && !name.ends_with(".keystore") && !name.ends_with(".p12") && !name.ends_with(".pem")
                || f.to_string_lossy().contains("/res/raw/"),
            "{}: key material in the tree",
            f.display()
        );
        if let Ok(t) = std::fs::read_to_string(&f) {
            assert!(
                !t.contains("BEGIN PRIVATE KEY") && !t.contains("BEGIN EC PRIVATE KEY") && !t.contains("BEGIN RSA PRIVATE KEY"),
                "{}: private key",
                f.display()
            );
            if name != "local.properties" {
                assert!(!t.contains("storePassword=") || name.ends_with(".kts"), "{}: password in tree", f.display());
            }
        }
    }
}

/// FR-02: typed text must not reach keyboard learning / autofill; every field goes through `PrivateTextField`.
#[test]
fn every_text_field_goes_through_private_text_field() {
    for (f, t) in kotlin_main() {
        for (n, l) in hits(&t, &["OutlinedTextField(", "TextField(", "BasicTextField("]) {
            let ok = f.ends_with("components/Components.kt") || l.contains("PrivateTextField(");
            assert!(ok, "{f}:{n}: use PrivateTextField (autocorrect off, incognito IME): `{}`", l.trim());
        }
    }
    let c = read("app/src/main/java/app/cipher/messenger/ui/components/Components.kt");
    assert!(c.contains("autoCorrectEnabled = false") && c.contains("PlatformImeOptions(\"nm\")"));
}

/// FR-03: Compose/Activity saved state is persisted by the system; secrets must never be put in it.
#[test]
fn saved_state_never_holds_secrets_or_message_text() {
    let secret_words = ["pin", "password", "secret", "key", "text", "draft", "message", "invite", "token", "plaintext", "body"];
    for (f, t) in kotlin_main() {
        for (n, l) in hits(&t, &["rememberSaveable", "SavedStateHandle", "onSaveInstanceState", "putString("]) {
            let lower = l.to_lowercase();
            let name = lower.split("var ").nth(1).and_then(|r| r.split_whitespace().next()).unwrap_or("");
            // an exact-word match on the variable name is enough to flag it; `step`, `url`, `understood`, `showPin` etc. are not secrets
            let bad =
                secret_words.iter().any(|w| name == *w || name.starts_with(&format!("{w}_")) || name.starts_with(&format!("chosen{w}")));
            assert!(!bad, "{f}:{n}: a secret-looking value is saved into system-persisted state: `{}`", l.trim());
        }
    }
}

/// FR-04: overlay/tapjacking and autofill defences exist and are applied to the real root view.
#[test]
fn overlay_and_autofill_defences_are_present() {
    let sa = read("app/src/main/java/app/cipher/messenger/SecureActivity.kt");
    for needle in [
        "setHideOverlayWindows(true)",
        "IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS",
        "filterTouchesWhenObscured = true",
        "ACCESSIBILITY_DATA_SENSITIVE_YES",
    ] {
        assert!(sa.contains(needle), "SecureActivity must contain {needle}");
    }
    let ma = read("app/src/main/java/app/cipher/messenger/MainActivity.kt");
    assert!(ma.contains("hardenRoot()"), "MainActivity must call hardenRoot() after setContent");
    let m = read("app/src/main/AndroidManifest.xml");
    assert!(m.contains("android.permission.HIDE_OVERLAY_WINDOWS"));
}

/// FR-06: attacker-controlled images must go through `SafeDecode` (header check, sub-sampling, OOM-safe).
#[test]
fn bitmap_decoding_of_untrusted_bytes_only_happens_in_safe_decode() {
    for (f, t) in kotlin_main() {
        for (n, l) in hits(&t, &["decodeByteArray(", "BitmapFactory.decodeStream(", "BitmapFactory.decodeFile("]) {
            assert!(f.ends_with("media/MediaSupport.kt"), "{f}:{n}: decode untrusted images with SafeDecode.bitmap: `{}`", l.trim());
        }
    }
    let m = read("app/src/main/java/app/cipher/messenger/media/MediaSupport.kt");
    assert!(m.contains("MAX_SOURCE_PIXELS") && m.contains("catch (_: Throwable)"));
}

/// ST-027: the Keystore wrapper must never RETURN the vault key and must zero its copies.
#[test]
fn keystore_wrapper_never_returns_the_vault_key_and_zeroes_its_copies() {
    let k = read("app/src/main/java/app/cipher/messenger/security/AndroidKeystoreCallbacks.kt");
    assert!(!k.contains("override fun unwrap("), "unwrap must hand the secret to a sink, not return it");
    assert!(k.contains("override fun unwrapInto("));
    assert!(k.matches("fill(0)").count() >= 2, "both wrap (its input) and unwrapInto (its output) must zero their arrays");
}

/// FR-11: leaving the foreground / screen-off must signal the engine and cancel the network on the calling thread BEFORE queueing the lock.
#[test]
fn background_and_screen_off_signal_the_lock_before_queueing_it() {
    let h = read("app/src/main/java/app/cipher/messenger/data/EngineHost.kt");
    assert!(h.contains("engine?.requestLock()") && h.contains("http.cancelAll()"));
    for f in ["fun onBackground()", "fun onScreenOff()"] {
        let body = &h[h.find(f).unwrap()..];
        let body = &body[..body.find("\n    }").unwrap()];
        assert!(body.contains("signalLockNow()"), "{f} must call signalLockNow() first");
    }
}

/// The shell validates the relay address (and pin) before the engine ever sees it (a misleading "secure storage" error once hid a pasted double URL).
/// The rules live in `RelayAddress` (JVM-unit-tested, mirrors the Rust descriptor); the view model can reach the host only through it.
#[test]
fn relay_address_is_validated_in_the_shell() {
    let ra = read("app/src/main/java/app/cipher/messenger/net/RelayAddress.kt");
    for needle in
        ["removePrefix(\"https://\")", "\"/@?# \\\\%\"", "lastIndexOf(\"://\")", ".onion", "need the certificate pin", "size == 32"]
    {
        assert!(ra.contains(needle), "RelayAddress must check {needle}");
    }
    let vm = read("app/src/main/java/app/cipher/messenger/data/AppViewModel.kt");
    let f = &vm[vm.find("fun configureRelay").unwrap()..];
    let f = &f[..f.find("fun updateRelayPin").unwrap()];
    assert!(
        f.contains("RelayAddress.parse(url, pin)") && f.contains("host.configureRelay(r.address)"),
        "only a parsed address reaches the host"
    );
    let host = read("app/src/main/java/app/cipher/messenger/data/EngineHost.kt");
    assert!(host.contains("fun configureRelay(address: RelayAddress)") && !host.contains("fun configureRelay(url: String"));
    assert!(host.contains("require(!address.isOnion || address.pinB64 != null)"));
}

/// The pinned-TLS component is the only place that may implement a trust manager. Its shape is checked so a "temporary" accept-all cannot slip in.
#[test]
fn the_pinned_tls_component_cannot_become_an_accept_all_trust_manager() {
    let t = read("app/src/main/java/app/cipher/messenger/net/PinnedTls.kt");
    // delegates to the platform trust manager for every host without a pin, and refuses when there is none
    assert!(
        t.contains("platform.checkServerTrusted(chain, authType, socket)")
            && t.contains("platform.checkServerTrusted(chain, authType, engine)")
    );
    assert!(t.contains("platform.checkServerTrusted(chain, authType)"));
    assert!(t.contains("platform trust manager unavailable") && t.contains("error("));
    // a pin compares the full SHA-256 of the SubjectPublicKeyInfo in constant time, and checks validity dates
    assert!(t.contains("MessageDigest.isEqual(spki, pin)") && t.contains("leaf.checkValidity()") && t.contains("SHA-256"));
    // no server-side trust, no empty bodies that accept, no host-name verifier
    assert!(t.matches("fun checkServerTrusted").count() == 3);
    assert!(!t.contains("HostnameVerifier") && !t.contains("trustAll") && !t.contains("ALLOW_ALL"));
    assert!(t.matches("throw CertificateException(\"client auth unsupported\")").count() == 3);
    // only OkHttpCallbacks wires it, and only with this component's own factory
    for (f, text) in kotlin_main() {
        if f.ends_with("net/PinnedTls.kt") {
            continue;
        }
        assert!(!text.contains("PinningTrustManager"), "{f}: the trust manager must not be used directly");
        if text.contains("sslSocketFactory(") {
            assert!(
                f.ends_with("net/OkHttpCallbacks.kt") && text.contains("sslSocketFactory(pinnedTls.socketFactory, pinnedTls.trustManager)"),
                "{f}"
            );
        }
    }
}
