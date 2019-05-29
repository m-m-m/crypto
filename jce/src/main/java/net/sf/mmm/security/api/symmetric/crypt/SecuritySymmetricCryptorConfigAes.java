package net.sf.mmm.security.api.symmetric.crypt;

import net.sf.mmm.security.api.crypt.SecurityCipherTransformation;
import net.sf.mmm.security.api.provider.SecurityProvider;

/**
 * SecurityCryptorAlgorithmSymmetricConfig for <a
 * href="https://en.wikipedia.org/wiki/Advanced_Encryption_Standard>AES</a>.<br>
 * <b>Attention:</b> JCA/JCE is buggy (creates a nonce of 12 on encryption but expects 16 bytes nonce on decryption,
 * etc.). Therefore you shall only use this with {@link SecurityProvider#BC BouncyCastle}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecuritySymmetricCryptorConfigAes extends SecuritySymmetricCryptorConfig {

  /** {@link SecurityCipherTransformation#getAlgorithm() Cipher algorithm} {@value}. */
  public static final String ALGORITHM_AES = "AES";

  /**
   * {@link SecurityCipherTransformation} for {@link #ALGORITHM_AES AES} with
   * {@link SecurityCipherTransformation#MODE_GCM GCM} and {@link SecurityCipherTransformation#PADDING_NONE no padding}.
   */
  public static final SecurityCipherTransformation TRANSFORMATION_AES_GCM_NOPADDING = new SecurityCipherTransformation(ALGORITHM_AES,
      SecurityCipherTransformation.MODE_GCM, SecurityCipherTransformation.PADDING_NONE);

  /**
   * The constructor.
   *
   * @param mode the {@link SecurityCipherTransformation#getMode() cipher mode}.
   * @param padding the {@link SecurityCipherTransformation#getPadding() cipher padding}.
   * @param provider the {@link SecurityProvider}.
   * @param nonceSize the {@link #getNonceSize() nonce-size}.
   */
  public SecuritySymmetricCryptorConfigAes(String mode, String padding, SecurityProvider provider, int nonceSize) {

    super(new SecurityCipherTransformation(ALGORITHM_AES, mode, padding), provider, nonceSize);
  }

  /**
   * The constructor.
   *
   * @param provider the {@link SecurityProvider}.
   */
  public SecuritySymmetricCryptorConfigAes(SecurityProvider provider) {

    this(provider, 16);
  }

  /**
   * The constructor.
   *
   * @param provider the {@link SecurityProvider}.
   * @param nonceSize the {@link #getNonceSize() nonce-size}.
   */
  public SecuritySymmetricCryptorConfigAes(SecurityProvider provider, int nonceSize) {

    super(TRANSFORMATION_AES_GCM_NOPADDING, provider, nonceSize);
  }

}
