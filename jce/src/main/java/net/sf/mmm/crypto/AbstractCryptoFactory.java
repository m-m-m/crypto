package net.sf.mmm.crypto;

/**
 * Abstract interface for any factory of this security library. All such factories are thread-safe and represent a
 * specific configuration (see {@link net.sf.mmm.crypto.algorithm.CryptoAlgorithmConfig}).
 *
 * @see net.sf.mmm.crypto.random.RandomFactory
 * @see net.sf.mmm.crypto.hash.HashFactory
 * @see net.sf.mmm.crypto.crypt.CryptorFactory
 * @see net.sf.mmm.crypto.asymmetric.sign.SignatureProcessorFactory
 * @see net.sf.mmm.crypto.asymmetric.key.AsymmetricKeyCreatorFactory
 * @see net.sf.mmm.crypto.symmetric.key.SymmetricKeyCreatorFactory
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract interface AbstractCryptoFactory {

}
