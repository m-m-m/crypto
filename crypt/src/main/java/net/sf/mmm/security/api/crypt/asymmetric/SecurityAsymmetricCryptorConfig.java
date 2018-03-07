package net.sf.mmm.security.api.crypt.asymmetric;

import net.sf.mmm.security.api.crypt.SecurityCryptorConfig;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyConfig;

/**
 * {@link SecurityCryptorConfig} for {@link net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyPair
 * asymmetric cryptography}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class SecurityAsymmetricCryptorConfig extends SecurityCryptorConfig<SecurityAsymmetricKeyConfig> {

  /**
   * The constructor.
   *
   * @param algorithm the {@link javax.crypto.Cipher#getAlgorithm() algorithm} for encryption and decryption.
   * @param keyAlgorithmConfig the corresponding {@link SecurityAsymmetricKeyConfig}.
   * @param nonceSize the {@link #getNonceSize() nonce size}.
   */
  public SecurityAsymmetricCryptorConfig(String algorithm, SecurityAsymmetricKeyConfig keyAlgorithmConfig,
      int nonceSize) {

    super(algorithm, keyAlgorithmConfig, nonceSize);
  }

  /**
   * @return {@code true} if this configuration supports {@link SecurityAsymmetricCryptorFactoryPrivatePublic},
   *         {@code false} otherwise.
   */
  public abstract boolean isPrivatePublic();

  /**
   * @return {@code true} if this configuration supports {@link SecurityAsymmetricCryptorFactoryPublicPrivate},
   *         {@code false} otherwise.
   */
  public abstract boolean isPublicPrivate();

}
