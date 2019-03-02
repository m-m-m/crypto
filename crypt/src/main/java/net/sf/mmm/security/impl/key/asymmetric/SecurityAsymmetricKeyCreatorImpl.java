package net.sf.mmm.security.impl.key.asymmetric;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.KeySpec;

import net.sf.mmm.security.api.key.SecurityKeyCreator;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyConfig;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyPair;
import net.sf.mmm.security.api.key.asymmetric.SecurityPrivateKey;
import net.sf.mmm.security.api.key.asymmetric.SecurityPublicKey;
import net.sf.mmm.security.api.random.SecurityRandomFactory;

/**
 * Implementation of {@link SecurityKeyCreator}.
 */
public class SecurityAsymmetricKeyCreatorImpl extends AbstractSecurityAsymmetricKeyCreator {

  private KeyFactory keyFactory;

  /**
   * The constructor.
   *
   * @param config the {@link SecurityAsymmetricKeyConfig}.
   * @param provider the security {@link Provider}.
   * @param randomFactory the {@link SecurityRandomFactory}.
   */
  public SecurityAsymmetricKeyCreatorImpl(SecurityAsymmetricKeyConfig config, Provider provider, SecurityRandomFactory randomFactory) {

    super(config, provider, randomFactory);
  }

  @Override
  public SecurityPrivateKey deserializePrivateKey(byte[] privateKeyData) {

    try {
      return this.config.deserializePrivateKey(privateKeyData, getKeyFactory());
    } catch (Exception e) {
      throw creationFailedException(e, PrivateKey.class);
    }
  }

  @Override
  public SecurityPublicKey deserializePublicKey(byte[] publicKeyData) {

    try {
      return this.config.deserializePublicKey(publicKeyData, getKeyFactory());
    } catch (Exception e) {
      throw creationFailedException(e, PublicKey.class);
    }
  }

  @Override
  public SecurityAsymmetricKeyPair deserializeKeyPair(byte[] keyPairData) {

    try {
      return this.config.deserializeKeyPair(keyPairData, getKeyFactory());
    } catch (Exception e) {
      throw creationFailedException(e, KeyPair.class);
    }
  }

  /**
   * @param privateKeySpec the {@link KeySpec} for {@link PrivateKey}.
   * @return the {@link PrivateKey}.
   * @see KeyFactory#generatePrivate(KeySpec)
   */
  public PrivateKey generatePrivateKey(KeySpec privateKeySpec) {

    try {
      return getKeyFactory().generatePrivate(privateKeySpec);
    } catch (Exception e) {
      throw creationFailedException(e, PrivateKey.class);
    }
  }

  /**
   * @param publicKeySpec the {@link KeySpec} for {@link PublicKey}.
   * @return the {@link PublicKey}.
   * @see KeyFactory#generatePublic(KeySpec)
   */
  public PublicKey generatePublicKey(KeySpec publicKeySpec) {

    try {
      return getKeyFactory().generatePublic(publicKeySpec);
    } catch (Exception e) {
      throw creationFailedException(e, PrivateKey.class);
    }
  }

  private KeyFactory getKeyFactory() {

    if (this.keyFactory == null) {
      try {
        Provider provider = getProvider();
        if (provider == null) {
          this.keyFactory = KeyFactory.getInstance(getAlgorithm());
        } else {
          this.keyFactory = KeyFactory.getInstance(getAlgorithm(), provider);
        }
      } catch (Exception e) {
        throw creationFailedException(e, KeyFactory.class);
      }
    }
    return this.keyFactory;
  }

}
