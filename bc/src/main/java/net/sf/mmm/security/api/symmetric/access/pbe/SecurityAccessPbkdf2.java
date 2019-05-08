package net.sf.mmm.security.api.symmetric.access.pbe;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmPbkdf2;
import net.sf.mmm.security.api.symmetric.crypt.SecuritySymmetricCryptorConfig;
import net.sf.mmm.security.api.symmetric.crypt.SecuritySymmetricCryptorConfigAes;
import net.sf.mmm.security.api.symmetric.key.pbe.SecuritySymmetricKeyConfigPbe;
import net.sf.mmm.security.api.symmetric.key.pbe.SecuritySymmetricKeyConfigPbkdf2;

/**
 * {@link SecurityAccessPbe} for {@link SecurityAlgorithmPbkdf2}.
 *
 * @since 1.0.0
 */
public class SecurityAccessPbkdf2 extends SecurityAccessPbe {

  /**
   * The constructor.
   *
   * @param keyConfig the {@link SecuritySymmetricKeyConfigPbkdf2}.
   * @param cryptorConfig the {@link SecuritySymmetricCryptorConfig}.
   */
  public SecurityAccessPbkdf2(SecuritySymmetricKeyConfigPbkdf2 keyConfig, SecuritySymmetricCryptorConfig cryptorConfig) {

    super(keyConfig, cryptorConfig);
  }

  /**
   * @return the {@link SecurityAccessPbkdf2} for {@link SecurityAlgorithmPbkdf2#ALGORITHM_PBKDF2_WITH_HMAC_SHA256} with
   *         a key length of {@code 256} bit.
   */
  public static SecurityAccessPbkdf2 ofPbkdf2HmacSha256() {

    return ofPbkdf2HmacSha256(256);
  }

  /**
   * @param keyLength the {@link SecuritySymmetricKeyConfigPbe#getKeyLength() key length}.
   * @return the {@link SecurityAccessPbkdf2} for {@link SecurityAlgorithmPbkdf2#ALGORITHM_PBKDF2_WITH_HMAC_SHA256} with
   *         the given key length.
   */
  public static SecurityAccessPbkdf2 ofPbkdf2HmacSha256(int keyLength) {

    SecuritySymmetricKeyConfigPbkdf2 keyConfig = new SecuritySymmetricKeyConfigPbkdf2(
        SecurityAlgorithmPbkdf2.ALGORITHM_PBKDF2_WITH_HMAC_SHA256, keyLength);
    return new SecurityAccessPbkdf2(keyConfig, SecuritySymmetricCryptorConfigAes.AES_GCM_256);
  }

}
