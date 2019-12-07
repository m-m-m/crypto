package io.github.mmm.crypto;

/**
 * Abstract interface for any factory of this security library. All such factories are thread-safe and represent a
 * specific configuration (see {@link io.github.mmm.crypto.algorithm.CryptoAlgorithmConfig}).
 *
 * @see io.github.mmm.crypto.random.RandomFactory
 * @see io.github.mmm.crypto.hash.HashFactory
 * @see io.github.mmm.crypto.crypt.CryptorFactory
 * @see io.github.mmm.crypto.asymmetric.sign.SignatureProcessorFactory
 * @see io.github.mmm.crypto.asymmetric.key.AsymmetricKeyCreatorFactory
 * @see io.github.mmm.crypto.symmetric.key.SymmetricKeyCreatorFactory
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract interface AbstractCryptoFactory {

}
