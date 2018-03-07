package net.sf.mmm.security.api.crypt.asymmetric;

import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyConfig;

/**
 * {@link SecurityAsymmetricCryptorConfig} for {@link SecurityAsymmetricCryptorFactoryBidirectional asymmetric
 * bidirectional cryptography}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class SecurityAsymmetricCryptorConfigBidirectional extends SecurityAsymmetricCryptorConfig {

  /**
   * The constructor.
   *
   * @param algorithm the {@link javax.crypto.Cipher#getAlgorithm() algorithm} for encryption and decryption.
   * @param keyAlgorithmConfig the corresponding {@link SecurityAsymmetricKeyConfig}.
   * @param nonceSize the {@link #getNonceSize() nonce size}.
   */
  public SecurityAsymmetricCryptorConfigBidirectional(String algorithm, SecurityAsymmetricKeyConfig keyAlgorithmConfig,
      int nonceSize) {

    super(algorithm, keyAlgorithmConfig, nonceSize);
  }

  @Override
  public boolean isPrivatePublic() {

    return true;
  }

  @Override
  public boolean isPublicPrivate() {

    return true;
  }

}
