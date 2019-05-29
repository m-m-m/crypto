package net.sf.mmm.security.api.key;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmConfig;
import net.sf.mmm.security.api.provider.SecurityProvider;

/**
 * Abstract base class of an {@link SecurityAlgorithmConfig algorithm configuration} for dealing with
 * {@link java.security.Key}s.
 *
 * @see SecurityKeyFactory
 * @see SecurityKeyCreator
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class SecurityKeyConfig extends SecurityAlgorithmConfig implements AbstractSecurityGetKeyLength {

  private final int keyLength;

  /**
   * The constructor.
   *
   * @param algorithm the {@link #getAlgorithm() algorithm}.
   * @param provider the {@link SecurityProvider}.
   * @param keyLength the {@link #getKeyLength() key length} in bits.
   */
  public SecurityKeyConfig(String algorithm, SecurityProvider provider, int keyLength) {

    super(algorithm, provider);
    this.keyLength = keyLength;
  }

  @Override
  public int getKeyLength() {

    return this.keyLength;
  }

}
