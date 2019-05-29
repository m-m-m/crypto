package net.sf.mmm.security.api.symmetric.key;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import net.sf.mmm.security.api.key.SecurityKeyConfig;
import net.sf.mmm.security.api.provider.SecurityProvider;

/**
 * {@link SecurityKeyConfig} for symmetric cryptography.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class SecuritySymmetricKeyConfig extends SecurityKeyConfig {

  private final SecuritySymmetricKeySpecFactory keySpecFactory;

  /**
   * The constructor.
   *
   * @param algorithm the {@link #getAlgorithm() algorithm}.
   * @param provider the {@link SecurityProvider}.
   * @param keyLength the {@link #getKeyLength() key length} in bits.
   * @param keySpecFactory the {@link #getKeySpecFactory() key spec factory}.
   */
  public SecuritySymmetricKeyConfig(String algorithm, SecurityProvider provider, int keyLength,
      SecuritySymmetricKeySpecFactory keySpecFactory) {

    super(algorithm, provider, keyLength);
    this.keySpecFactory = keySpecFactory;
  }

  /**
   * @return the {@link SecuritySymmetricKeySpecFactory}.
   */
  public SecuritySymmetricKeySpecFactory getKeySpecFactory() {

    return this.keySpecFactory;
  }

  /**
   * @param key the {@link SecretKey}.
   * @param keyFactory the {@link SecretKeyFactory}.
   * @return the {@link #getKeyLength() key length} of the given {@link SecretKey}.
   */
  public abstract int getKeyLength(SecretKey key, SecretKeyFactory keyFactory);
}
