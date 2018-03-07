package net.sf.mmm.security.api.key;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmConfig;

/**
 * Abstract base class of an {@link SecurityAlgorithmConfig algorithm configuration} for dealing with
 * {@link SecurityKey}s.
 *
 * @see SecurityKeyFactory
 * @see SecurityKeyCreator
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class SecurityKeyConfig extends SecurityAlgorithmConfig {

  private final int keyLength;

  /**
   * The constructor.
   *
   * @param algorithm the {@link #getAlgorithm() algorithm}.
   * @param keyLength the {@link #getKeyLength() key length} in bits.
   */
  public SecurityKeyConfig(String algorithm, int keyLength) {

    super(algorithm);
    this.keyLength = keyLength;
  }

  /**
   * @return the length of the key in bits. The bigger the key length the stronger and more secure the encryption but
   *         also the more performance is required for computation. Reasonable values depend on the
   *         {@link #getAlgorithm() algorithm}: A recent value for RSA is 4096 bits while for PBKDF2 256 is sufficient.
   */
  public int getKeyLength() {

    return this.keyLength;
  }

}
