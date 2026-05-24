package tech.atlasnexus.ai2work.wallet

import org.bouncycastle.crypto.digests.KeccakDigest

/**
 * Keccak-256 (Ethereum-compatible) backed by BouncyCastle's audited implementation.
 * Replaces the previous pure-Kotlin implementation per security audit recommendation:
 * platform-verified library bindings eliminate timing-attack and GC-pressure risks.
 */
object Keccak256 {

    /** Returns the 32-byte Keccak-256 digest of [input]. */
    fun digest(input: ByteArray): ByteArray {
        val digest = KeccakDigest(256)
        digest.update(input, 0, input.size)
        val out = ByteArray(32)
        digest.doFinal(out, 0)
        return out
    }
}
