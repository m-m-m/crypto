package net.sf.mmm.crypto.key;

import net.sf.mmm.crypto.algorithm.CryptoAlgorithmConfig;
import net.sf.mmm.crypto.provider.SecurityProvider;

/**
 * Abstract base class of an {@link CryptoAlgorithmConfig algorithm configuration} for dealing with
 * {@link java.security.Key}s.
 *
 * @see KeyCreatorFactory
 * @see KeyCreator
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class KeyConfig extends CryptoAlgorithmConfig implements AbstractGetKeyLength {

  private final int keyLength;

  /**
   * The constructor.
   *
   * @param algorithm the {@link #getAlgorithm() algorithm}.
   * @param provider the {@link SecurityProvider}.
   * @param keyLength the {@link #getKeyLength() key length} in bits.
   */
  public KeyConfig(String algorithm, SecurityProvider provider, int keyLength) {

    super(algorithm, provider);
    this.keyLength = keyLength;
  }

  @Override
  public int getKeyLength() {

    return this.keyLength;
  }

}
