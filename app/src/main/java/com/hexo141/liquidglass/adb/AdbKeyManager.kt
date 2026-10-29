package com.hexo141.liquidglass.adb

import android.content.Context
import android.util.Base64
import android.util.Log
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.pkcs.RSAPrivateKey
import org.bouncycastle.asn1.pkcs.RSAPublicKey
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPrivateKey as JcaRsaPrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAKeyGenParameterSpec
import java.util.Date
import java.util.Locale

/**
 * RSA 2048 key and self-signed certificate used for ADB pairing.
 *
 * The private key signs the TLS client handshake and the RSA public key is sent to adbd in
 * Android's ADB public key format. Both are persisted in private SharedPreferences so repeat
 * pairings reuse the same key that adbd may already trust.
 */
class AdbKeyManager(context: Context) {

    companion object {
        private const val TAG = "AdbKeyManager"
        private const val PREF_NAME = "adb_pairing_key"
        private const val KEY_PRIVATE = "private_key_pkcs8"
        private const val KEY_CERT = "certificate_der"

        /** Certificate validity end (2031-12-31), matching the usual Android self-signed cert. */
        private const val NOT_AFTER_MILLIS = 1956528000_000L

        /** Set once [importPrivateKey] succeeded, so the UI can say where the identity came from. */
        private const val KEY_IMPORTED = "imported"

        /** Captures the base64 body of a PEM block, tolerating CRLF and surrounding text. */
        private val PEM_BLOCK = Regex(
            "-----BEGIN [A-Z ]*PRIVATE KEY-----(.*?)-----END [A-Z ]*PRIVATE KEY-----",
            RegexOption.DOT_MATCHES_ALL,
        )

        /**
         * Whether a key pair was generated before (i.e. a pairing was attempted at least once).
         * Used to try a silent direct connection after the "paired" flag was introduced.
         */
        fun hasStoredKey(context: Context): Boolean =
            context.applicationContext
                .getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)
                .getString(KEY_PRIVATE, null) != null
    }

    private val preferences = context.applicationContext
        .getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE)

    val privateKey: PrivateKey
    val certificate: X509Certificate

    init {
        val loaded = load()
        if (loaded != null) {
            privateKey = loaded.first
            certificate = loaded.second
        } else {
            val generated = generate()
            privateKey = generated.first
            certificate = generated.second
            save(privateKey, certificate)
        }
        Log.d(TAG, "adb key ready: ${certificate.subjectX500Principal}")
    }

    private fun load(): Pair<PrivateKey, X509Certificate>? {
        val privateBytes = preferences.getString(KEY_PRIVATE, null) ?: return null
        val certBytes = preferences.getString(KEY_CERT, null) ?: return null
        return try {
            val key = KeyFactory.getInstance("RSA")
                .generatePrivate(PKCS8EncodedKeySpec(Base64.decode(privateBytes, Base64.NO_WRAP))) as PrivateKey
            val cert = CertificateFactory.getInstance("X.509")
                .generateCertificate(ByteArrayInputStream(Base64.decode(certBytes, Base64.NO_WRAP))) as X509Certificate
            key to cert
        } catch (e: Throwable) {
            Log.w(TAG, "stored adb key is unusable, regenerating", e)
            null
        }
    }

    private fun save(privateKey: PrivateKey, certificate: X509Certificate) {
        preferences.edit()
            .putString(KEY_PRIVATE, Base64.encodeToString(privateKey.encoded, Base64.NO_WRAP))
            .putString(KEY_CERT, Base64.encodeToString(certificate.encoded, Base64.NO_WRAP))
            .apply()
    }

    private fun generate(): Pair<PrivateKey, X509Certificate> {
        val generator = KeyPairGenerator.getInstance("RSA")
        generator.initialize(RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4))
        val keyPair = generator.generateKeyPair()

        val name = X500Name("CN=00")
        val signer = JcaContentSignerBuilder("SHA256withRSA").build(keyPair.private)
        val holder = X509v3CertificateBuilder(
            name,
            BigInteger.ONE,
            Date(0),
            Date(NOT_AFTER_MILLIS),
            Locale.ROOT,
            name,
            SubjectPublicKeyInfo.getInstance(keyPair.public.encoded)
        ).build(signer)

        val certificate = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(holder.encoded)) as X509Certificate

        return keyPair.private to certificate
    }

    /**
     * Replaces the stored identity with a private key generated elsewhere.
     *
     * adbd only accepts a key it already knows, so an app that generated its own pair on first
     * launch stays locked out of a device whose `adb tcpip` port never shows the "allow debugging"
     * prompt. Importing the key of a client that connected before is the only way in without root,
     * because adbd keeps that allow-list under `/data/misc/adb`, which the shell user cannot write.
     *
     * @param pem a PKCS#8 block, including a whole `adbkey` file or the text pasted out of one.
     *   The `-----BEGIN`/`-----END` lines are optional.
     * @return `true` when the key parsed, was self-signed and replaced the stored one.
     */
    fun importPrivateKey(pem: String): Boolean {
        val body = PEM_BLOCK.find(pem)?.groupValues?.get(1) ?: pem.filterNot { it.isWhitespace() }
        val decoded = runCatching { Base64.decode(body, Base64.DEFAULT) }.getOrNull() ?: return false
        val key = runCatching {
            KeyFactory.getInstance("RSA")
                .generatePrivate(PKCS8EncodedKeySpec(decoded)) as JcaRsaPrivateKey
        }.getOrNull() ?: return false
        // adbd verifies signatures against a public key derived from this private key; the
        // certificate itself is never inspected, so a throwaway self-signed one is enough.
        val certificate = runCatching { selfSign(key) }.getOrNull() ?: return false
        save(key, certificate)
        Log.d(TAG, "imported an external adb key: ${certificate.subjectX500Principal}")
        return true
    }

    /** Wraps [privateKey] in a self-signed certificate carrying the matching public key. */
    private fun selfSign(privateKey: JcaRsaPrivateKey): X509Certificate {
        val rsa = RSAPrivateKey.getInstance(PrivateKeyInfo.getInstance(privateKey.encoded))
        val publicKey = KeyFactory.getInstance("RSA").generatePublic(
            SubjectPublicKeyInfo(RSAPublicKey(rsa.modulus, rsa.publicExponent))
        )
        val name = X500Name("CN=00")
        val signer = JcaContentSignerBuilder("SHA256withRSA").build(privateKey)
        val holder = X509v3CertificateBuilder(
            name,
            BigInteger.ONE,
            Date(0),
            Date(NOT_AFTER_MILLIS),
            Locale.ROOT,
            name,
            SubjectPublicKeyInfo.getInstance(publicKey.encoded)
        ).build(signer)
        return CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(holder.encoded)) as X509Certificate
    }

    /** Whether the identity in use was imported instead of generated on this device. */
    fun isImported(): Boolean = preferences.getBoolean(KEY_IMPORTED, false)
}
