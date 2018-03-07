package net.sf.mmm.security.api.crypt.symmetric;

import net.sf.mmm.security.api.crypt.SecurityCryptorConfig;
import net.sf.mmm.security.api.key.symmetric.SecuritySymmetricKey;
import net.sf.mmm.security.api.key.symmetric.SecuritySymmetricKeyConfig;

/**
 * {@link SecurityCryptorConfig} for {@link SecuritySymmetricKey}
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecuritySymmetricCryptorConfig extends SecurityCryptorConfig<SecuritySymmetricKeyConfig> {

  /**
   * The constructor.
   *
   * @param algorithm the {@link javax.crypto.Cipher#getAlgorithm() algorithm} for encryption and decryption.
   * @param keyAlgorithmConfig the corresponding {@link SecuritySymmetricKeyConfig}.
   * @param nonceSize the {@link #getNonceSize() nonce size}.
   */
  public SecuritySymmetricCryptorConfig(String algorithm, SecuritySymmetricKeyConfig keyAlgorithmConfig,
      int nonceSize) {

    super(algorithm, keyAlgorithmConfig, nonceSize);
  }

}
