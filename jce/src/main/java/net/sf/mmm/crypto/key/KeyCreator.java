package net.sf.mmm.crypto.key;

import net.sf.mmm.crypto.algorithm.CryptoAlgorithm;

/**
 * Abstract interface for dealing with cryptographic keys. As symmetric and asymmetric key creation are so different
 * there is no common method here. This might change in the future.
 *
 * @see net.sf.mmm.crypto.asymmetric.key.AsymmetricKeyCreator
 * @see net.sf.mmm.crypto.symmetric.key.SymmetricKeyCreator
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract interface KeyCreator extends CryptoAlgorithm {

  /**
   * @return the length of the key in bits. The bigger the key length the stronger and more secure the encryption but
   *         also the more computation power is required. Reasonable values depend on the {@link #getAlgorithm()
   *         algorithm}: A recent value for RSA is 4096 bits while for PBKDF2 256 may be sufficient.
   */
  int getKeyLength();

}
