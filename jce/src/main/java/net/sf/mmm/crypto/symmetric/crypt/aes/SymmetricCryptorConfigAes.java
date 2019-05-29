package net.sf.mmm.crypto.symmetric.crypt.aes;

import net.sf.mmm.crypto.crypt.CipherTransformation;
import net.sf.mmm.crypto.provider.SecurityProvider;
import net.sf.mmm.crypto.symmetric.crypt.SymmetricCryptorConfig;

/**
 * SecurityCryptorAlgorithmSymmetricConfig for <a href="https://en.wikipedia.org/wiki/Advanced_Encryption_Standard>
 * AES</a>.<br>
 * <b>Attention:</b> JCA/JCE is buggy (creates a nonce of 12 on encryption but expects 16 bytes nonce on decryption,
 * etc.). Therefore you shall only use this with {@link SecurityProvider#BC BouncyCastle}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SymmetricCryptorConfigAes extends SymmetricCryptorConfig {

  /** {@link CipherTransformation#getAlgorithm() Cipher algorithm} {@value}. */
  public static final String ALGORITHM_AES = "AES";

  /**
   * {@link CipherTransformation} for {@link #ALGORITHM_AES AES} with {@link CipherTransformation#MODE_GCM GCM} and
   * {@link CipherTransformation#PADDING_NONE no padding}.
   */
  public static final CipherTransformation TRANSFORMATION_AES_GCM_NOPADDING = new CipherTransformation(ALGORITHM_AES,
      CipherTransformation.MODE_GCM, CipherTransformation.PADDING_NONE);

  /**
   * The constructor.
   *
   * @param mode the {@link CipherTransformation#getMode() cipher mode}.
   * @param padding the {@link CipherTransformation#getPadding() cipher padding}.
   * @param provider the {@link SecurityProvider}.
   * @param nonceSize the {@link #getNonceSize() nonce-size}.
   */
  public SymmetricCryptorConfigAes(String mode, String padding, SecurityProvider provider, int nonceSize) {

    super(new CipherTransformation(ALGORITHM_AES, mode, padding), provider, nonceSize);
  }

  /**
   * The constructor.
   *
   * @param provider the {@link SecurityProvider}.
   */
  public SymmetricCryptorConfigAes(SecurityProvider provider) {

    this(provider, 16);
  }

  /**
   * The constructor.
   *
   * @param provider the {@link SecurityProvider}.
   * @param nonceSize the {@link #getNonceSize() nonce-size}.
   */
  public SymmetricCryptorConfigAes(SecurityProvider provider, int nonceSize) {

    super(TRANSFORMATION_AES_GCM_NOPADDING, provider, nonceSize);
  }

}
