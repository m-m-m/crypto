package net.sf.mmm.security.api.key.symmetric;

import net.sf.mmm.security.api.key.SecurityKeyConfig;

/**
 * {@link SecurityKeyConfig} for {@link SecuritySymmetricKey symmetric cryptography}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecuritySymmetricKeyConfig extends SecurityKeyConfig implements SecuritySymmetricKeyConstants {

  private final SecuritySymmetricKeySpecFactory keySpecFactory;

  /**
   * The constructor.
   *
   * @param algorithm the {@link #getAlgorithm() algorithm}.
   * @param keyLength the {@link #getKeyLength() key length} in bits.
   * @param keySpecFactory the {@link #getKeySpecFactory() key spec factory}.
   */
  public SecuritySymmetricKeyConfig(String algorithm, int keyLength, SecuritySymmetricKeySpecFactory keySpecFactory) {

    super(algorithm, keyLength);
    this.keySpecFactory = keySpecFactory;
  }

  /**
   * @return the {@link SecuritySymmetricKeySpecFactory}.
   */
  public SecuritySymmetricKeySpecFactory getKeySpecFactory() {

    return this.keySpecFactory;
  }

}
