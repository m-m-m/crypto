package net.sf.mmm.security.impl.key.symmetric;

import java.security.KeyFactory;
import java.security.Provider;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;

import net.sf.mmm.security.api.key.SecurityKeyCreator;
import net.sf.mmm.security.api.key.symmetric.SecuritySymmetricKey;
import net.sf.mmm.security.api.key.symmetric.SecuritySymmetricKeyConfig;
import net.sf.mmm.security.api.key.symmetric.SecuritySymmetricKeyCreator;
import net.sf.mmm.security.impl.AbstractSecurityAlgorithmWithProvider;

/**
 * Implementation of {@link SecurityKeyCreator}.
 */
public class SecuritySymmetricKeyCreatorImpl extends AbstractSecurityAlgorithmWithProvider implements SecuritySymmetricKeyCreator {

  private final SecuritySymmetricKeyConfig config;

  private SecretKeyFactory keyFactory;

  /**
   * The constructor.
   *
   * @param config the {@link SecuritySymmetricKeyConfig}.
   * @param provider the security {@link Provider}.
   */
  public SecuritySymmetricKeyCreatorImpl(SecuritySymmetricKeyConfig config, Provider provider) {

    super(provider);
    this.config = config;
  }

  @Override
  public String getAlgorithm() {

    return this.config.getAlgorithm();
  }

  @Override
  public SecuritySymmetricKey createKey(String password) {

    try {
      KeySpec keySpec = this.config.getKeySpecFactory().createKeySpec(password);
      SecretKey secretKey = getKeyFactory().generateSecret(keySpec);
      return createKey(secretKey);
    } catch (Exception e) {
      throw new IllegalStateException("Failed to create key pair for algorithm '" + getAlgorithm() + "'.", e);
    }
  }

  @Override
  public SecuritySymmetricKey deserializeKey(byte[] key) {

    return createKey(new SecretKeySpec(key, getAlgorithm()));
  }

  private SecretKeyFactory getKeyFactory() {

    if (this.keyFactory == null) {
      try {
        Provider provider = getProvider();
        if (provider == null) {
          this.keyFactory = SecretKeyFactory.getInstance(getAlgorithm());
        } else {
          this.keyFactory = SecretKeyFactory.getInstance(getAlgorithm(), provider);
        }
      } catch (Exception e) {
        throw creationFailedException(e, KeyFactory.class);
      }
    }
    return this.keyFactory;
  }

}
