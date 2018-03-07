package net.sf.mmm.security.api.crypt.symmetric;

import net.sf.mmm.security.api.key.symmetric.SecuritySymmetricKeyConfig;
import net.sf.mmm.security.api.key.symmetric.SecuritySymmetricKeyConfigPbkdf2;

/**
 * SecurityCryptorAlgorithmSymmetricConfig for <a
 * href="https://en.wikipedia.org/wiki/Advanced_Encryption_Standard>AES</a>.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecuritySymmetricCryptorConfigAes extends SecuritySymmetricCryptorConfig {

  /**
   * AES with GCM and no padding using {@link SecuritySymmetricKeyConfigPbkdf2#PBKDF2_WITH_HMAC_SHA256} for
   * password.<br>
   * <b>Attention:</b> JCA/JCE is buggy (creates a nonce of 12 on encryption but expects 16 bytes nonce on decryption,
   * etc.). Therefore you shall only use this with {@link org.bouncycastle.jce.provider.BouncyCastleProvider}.
   */
  public static final SecuritySymmetricCryptorConfigAes AES_GCM_256 = new SecuritySymmetricCryptorConfigAes(
      "AES/GCM/NoPadding", SecuritySymmetricKeyConfigPbkdf2.PBKDF2_WITH_HMAC_SHA256, 16);

  /**
   * The constructor.
   *
   * @param algorithm
   * @param keyAlgorithmConfig
   */
  private SecuritySymmetricCryptorConfigAes(String algorithm, SecuritySymmetricKeyConfig keyAlgorithmConfig,
      int nonceSize) {

    super(algorithm, keyAlgorithmConfig, nonceSize);
  }

}
