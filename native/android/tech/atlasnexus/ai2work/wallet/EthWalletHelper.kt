package tech.atlasnexus.ai2work.wallet

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.signers.HMacDSAKCalculator
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import java.math.BigInteger
import java.security.*
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

object EthWalletHelper {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val ENC_KEY_ALIAS = "ai2work_wallet_aes"
    private const val PREFS_NAME = "ai2work_eth"
    private const val PREF_KEY = "enc_key"

    private val EC_SPEC: ECNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec("secp256k1")
    private val EC_DOMAIN = ECDomainParameters(EC_SPEC.curve, EC_SPEC.g, EC_SPEC.n, EC_SPEC.h)
    private val CURVE_N: BigInteger = EC_SPEC.n
    private val HALF_N: BigInteger = CURVE_N.shiftRight(1)

    lateinit var appContext: Context

    init {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
        Security.insertProviderAt(BouncyCastleProvider(), 1)
    }

    fun createWallet(): String {
        val kpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME)
        kpg.initialize(ECGenParameterSpec("secp256k1"))
        val kp = kpg.generateKeyPair()

        val rawPriv = (kp.private as org.bouncycastle.jce.interfaces.ECPrivateKey).d.toByteArray()
        val ciphertext = aesEncrypt(rawPriv)

        appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(PREF_KEY, Base64.encodeToString(ciphertext, Base64.NO_WRAP))
            .apply()
        return pubKeyToAddress(kp.public as java.security.interfaces.ECPublicKey)
    }

    fun getAddress(): String? {
        val kp = loadKeyPair() ?: return null
        return pubKeyToAddress(kp.public as java.security.interfaces.ECPublicKey)
    }

    fun exists(): Boolean {
        val p = appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return p.contains(PREF_KEY)
    }

    fun delete() {
        appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit().clear().apply()
        try {
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE); ks.load(null)
            if (ks.containsAlias(ENC_KEY_ALIAS)) ks.deleteEntry(ENC_KEY_ALIAS)
        } catch (_: Exception) {}
    }

    fun signMessage(message: String): String {
        val kp = loadKeyPair() ?: throw IllegalStateException("No wallet")
        val prefix = "\u0019Ethereum Signed Message:\n"
        val msg = (prefix + message.length.toString() + message).toByteArray(Charsets.UTF_8)
        val hash = Keccak256.digest(msg)
        return signDigestWithRecovery(hash, kp.private as org.bouncycastle.jce.interfaces.ECPrivateKey)
    }

    fun signTransaction(
        to: String, value: BigInteger, data: ByteArray,
        nonce: Long, gasLimit: BigInteger,
        maxFeePerGas: BigInteger, maxPriorityFeePerGas: BigInteger,
        chainId: Long
    ): String {
        val kp = loadKeyPair() ?: throw IllegalStateException("No wallet")

        val rlp = RLP.list(
            RLP.long(chainId), RLP.long(nonce),
            RLP.bigint(maxPriorityFeePerGas), RLP.bigint(maxFeePerGas),
            RLP.bigint(gasLimit), RLP.address(to),
            RLP.bigint(value), RLP.bytes(data),
            RLP.list()
        )
        val unsigned = byteArrayOf(0x02) + rlp
        val hash = Keccak256.digest(unsigned)
        val (r, s, v) = signForRecovery(hash, kp.private as org.bouncycastle.jce.interfaces.ECPrivateKey)

        return "0x02" + bytesToHex(
            RLP.list(
                RLP.long(chainId), RLP.long(nonce),
                RLP.bigint(maxPriorityFeePerGas), RLP.bigint(maxFeePerGas),
                RLP.bigint(gasLimit), RLP.address(to),
                RLP.bigint(value), RLP.bytes(data),
                RLP.list(),
                if (v.toLong() % 2 == 0L) byteArrayOf() else byteArrayOf(0x01),
                RLP.bigint(r), RLP.bigint(s)
            )
        )
    }

    // ─── Private ───

    private fun loadKeyPair(): KeyPair? {
        val b64 = appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).getString(PREF_KEY, null) ?: return null
        val raw = aesDecrypt(Base64.decode(b64, Base64.NO_WRAP))
        val d = BigInteger(1, raw)
        val q = EC_SPEC.g.multiply(d).normalize()

        val kf = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME)
        val ecParams = java.security.spec.ECParameterSpec(
            java.security.spec.EllipticCurve(
                java.security.spec.ECFieldFp(EC_SPEC.curve.field.characteristic),
                EC_SPEC.curve.a.toBigInteger(), EC_SPEC.curve.b.toBigInteger()
            ),
            java.security.spec.ECPoint(EC_SPEC.g.affineXCoord.toBigInteger(), EC_SPEC.g.affineYCoord.toBigInteger()),
            EC_SPEC.n, EC_SPEC.h.toInt()
        )
        val pub = kf.generatePublic(java.security.spec.ECPublicKeySpec(
            java.security.spec.ECPoint(q.affineXCoord.toBigInteger(), q.affineYCoord.toBigInteger()),
            ecParams
        ))
        val priv = kf.generatePrivate(java.security.spec.ECPrivateKeySpec(d, ecParams))
        return KeyPair(pub, priv)
    }

    private fun pubKeyToAddress(pub: java.security.interfaces.ECPublicKey): String {
        val x = padLeft32(pub.w.affineX.toByteArray())
        val y = padLeft32(pub.w.affineY.toByteArray())
        val uncomp = byteArrayOf(0x04) + x + y
        val hash = Keccak256.digest(uncomp)
        return "0x" + bytesToHex(hash.copyOfRange(12, 32))
    }

    private fun signDigestWithRecovery(hash: ByteArray, priv: org.bouncycastle.jce.interfaces.ECPrivateKey): String {
        val (r, s, v) = signForRecovery(hash, priv)
        return "0x" + bytesToHex(padLeft32(r.toByteArray()) + padLeft32(s.toByteArray()) + byteArrayOf((v + 27).toByte()))
    }

    private fun signForRecovery(hash: ByteArray, priv: org.bouncycastle.jce.interfaces.ECPrivateKey): Triple<BigInteger, BigInteger, Byte> {
        val signer = ECDSASigner(HMacDSAKCalculator(SHA256Digest()))
        signer.init(true, ECPrivateKeyParameters(priv.d, EC_DOMAIN))
        val comps = signer.generateSignature(hash)
        val r = comps[0] as BigInteger
        var s = comps[1] as BigInteger
        if (s > HALF_N) s = CURVE_N.subtract(s)

        val pubRecover = EC_SPEC.g.multiply(priv.d).normalize()
        var recId: Byte = -1
        for (i in 0..3) {
            val recovered = recoverPubKey(i, r, s, hash)
            if (recovered != null && recovered == pubRecover) { recId = i.toByte(); break }
        }
        if (recId < 0) recId = 0
        return Triple(r, s, recId)
    }

    private fun recoverPubKey(recId: Int, r: BigInteger, s: BigInteger, hash: ByteArray): org.bouncycastle.math.ec.ECPoint? {
        if (recId < 0 || recId > 3) return null
        val curve = EC_SPEC.curve
        val field = curve.field.characteristic

        val x = if (recId >= 2) r.add(CURVE_N) else r
        if (x >= field) return null

        val x3 = x.modPow(BigInteger.valueOf(3), field)
        val ax = curve.a.toBigInteger().multiply(x).mod(field)
        val b = curve.b.toBigInteger()
        val rhs = x3.add(ax).add(b).mod(field)
        val y = rhs.modPow(field.add(BigInteger.ONE).divide(BigInteger.valueOf(4)), field)
        if (y.multiply(y).mod(field) != rhs) return null

        val yFinal = if (y.testBit(0) == (recId % 2 == 0)) y else field.subtract(y)
        return curve.createPoint(x, yFinal).normalize()
    }

    // ─── AES/GCM ───

    private fun aesEncrypt(plain: ByteArray): ByteArray {
        val key = getOrCreateAesKey()
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key)
        return c.iv + c.doFinal(plain)
    }

    private fun aesDecrypt(pkg: ByteArray): ByteArray {
        val iv = pkg.copyOfRange(0, 12)
        val ct = pkg.copyOfRange(12, pkg.size)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, getOrCreateAesKey(), GCMParameterSpec(128, iv))
        return c.doFinal(ct)
    }

    private fun getOrCreateAesKey(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE); ks.load(null)
        if (ks.containsAlias(ENC_KEY_ALIAS))
            return (ks.getEntry(ENC_KEY_ALIAS, null) as KeyStore.SecretKeyEntry).secretKey
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        kg.init(KeyGenParameterSpec.Builder(ENC_KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256).build())
        return kg.generateKey()
    }

    private fun padLeft32(b: ByteArray): ByteArray {
        return if (b.size >= 32) b.copyOfRange(b.size - 32, b.size)
        else ByteArray(32).also { System.arraycopy(b, 0, it, 32 - b.size, b.size) }
    }

    @JvmStatic fun bytesToHex(bytes: ByteArray): String {
        val hex = "0123456789abcdef"
        return String(CharArray(bytes.size * 2).also {
            for (i in bytes.indices) {
                val v = bytes[i].toInt() and 0xFF
                it[i * 2] = hex[v shr 4]
                it[i * 2 + 1] = hex[v and 0xF]
            }
        })
    }
}
