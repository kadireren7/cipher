package app.cipher.messenger.net

import java.util.Base64

/**
 * A relay address as the user types or scans it, validated with the SAME rules as the Rust `RelayDescriptor` (https only, canonical host, no user info /
 * path / query / fragment, `.onion` hosts REQUIRE a certificate pin). Pure Kotlin so it is unit-testable on the JVM.
 *
 * The pin is the SHA-256 of the relay certificate's public key (SubjectPublicKeyInfo). It is accepted in the forms operators actually see:
 *  `sha256/BASE64` (OkHttp / `cipherctl.sh onion-cert`), `sha256//BASE64` (curl), plain standard or URL-safe base64, or 64 hex digits; and is normalised to
 *  unpadded URL-safe base64 of exactly 32 bytes.
 */
data class RelayAddress(val url: String, val pinB64: String?) {
    val isOnion: Boolean get() = host(url).endsWith(".onion")

    sealed interface Result {
        data class Ok(val address: RelayAddress) : Result
        data class Bad(val reason: String) : Result
    }

    companion object {
        fun host(url: String): String = url.removePrefix("https://").substringBefore(':').lowercase()

        fun parse(urlInput: String, pinInput: String?): Result {
            val u = urlInput.trim().removeSuffix("/")
            val rest = u.removePrefix("https://")
            if (rest == u) return Result.Bad("The server address must start with https://")
            if (rest.isEmpty() || rest.any { it in "/@?# \\%" } || u.indexOf("://") != u.lastIndexOf("://")) {
                return Result.Bad("Enter the address like https://relay.example.org or https://relay.example.org:8443")
            }
            val host = rest.substringBefore(':').lowercase()
            val port = if (rest.contains(':')) rest.substringAfter(':') else null
            if (port != null && (port.isEmpty() || port.length > 5 || !port.all { it.isDigit() } || port.toInt() !in 1..65535)) {
                return Result.Bad("The port number is not valid")
            }
            if (host.isEmpty() ||
                host.length > 253 ||
                host.startsWith('.') ||
                host.startsWith('-') ||
                host.endsWith('.') ||
                host.endsWith('-') ||
                host.contains("..") ||
                !host.all { it in 'a'..'z' || it in '0'..'9' || it == '.' || it == '-' }
            ) {
                return Result.Bad("The host name is not valid")
            }
            val canonical = "https://" + host + (port?.let { ":$it" } ?: "")
            val pin = pinInput?.trim()?.takeIf { it.isNotEmpty() }?.let {
                normalisePin(it)
                    ?: return Result.Bad("The certificate pin is not valid (expected a SHA-256 key hash)")
            }
            if (host.endsWith(".onion") && pin == null) {
                return Result.Bad("Onion servers need the certificate pin that came with the invitation")
            }
            return Result.Ok(RelayAddress(canonical, pin))
        }

        /** Returns unpadded URL-safe base64 of 32 bytes, or null if the text is not a SHA-256 hash in any accepted form. */
        fun normalisePin(text: String): String? {
            var t = text.trim()
            for (prefix in listOf("sha256//", "sha256/")) {
                if (t.startsWith(prefix, ignoreCase = true)) {
                    t = t.substring(prefix.length)
                    break
                }
            }
            val bytes: ByteArray? = when {
                t.length == 64 && t.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' } ->
                    ByteArray(32) { i -> t.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
                else -> runCatching {
                    val urlSafe = t.replace('+', '-').replace('/', '_').trimEnd('=')
                    Base64.getUrlDecoder().decode(urlSafe)
                }.getOrNull()
            }
            return bytes?.takeIf { it.size == 32 }?.let { Base64.getUrlEncoder().withoutPadding().encodeToString(it) }
        }
    }
}
