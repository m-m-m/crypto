package net.sf.mmm.security.api.symmetric.crypt;

import net.sf.mmm.security.api.crypt.SecurityCryptorConfig;
import net.sf.mmm.security.api.provider.SecurityProvider;
import net.sf.mmm.security.api.symmetric.key.SecuritySymmetricKeyConfig;

/**
 * {@link SecurityCryptorConfig} for {@link SecuritySymmetricCryptorFactory symmetric encryption}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecuritySymmetricCryptorConfig extends SecurityCryptorConfig {

  /**
   * The constructor.
   *
   * @param algorithm the {@link javax.crypto.Cipher#getAlgorithm() algorithm} for encryption and decryption.
   * @param nonceSize the {@link #getNonceSize() nonce size}.
   * @param provider the {@link SecurityProvider}.
   * @param keyAlgorithmConfig the corresponding {@link SecuritySymmetricKeyConfig}.
   */
  public SecuritySymmetricCryptorConfig(String algorithm, SecurityProvider provider, int nonceSize,
      SecuritySymmetricKeyConfig keyAlgorithmConfig) {

    super(algorithm, provider, nonceSize);
  }

}
