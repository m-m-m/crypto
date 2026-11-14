package io.github.mmm.crypto.symmetric.crypt.aes;

import io.github.mmm.crypto.crypt.CipherTransformation;
import io.github.mmm.crypto.provider.SecurityProvider;
import io.github.mmm.crypto.symmetric.crypt.SymmetricCryptorConfig;

/// SecurityCryptorAlgorithmSymmetricConfig for
/// <a href="https://en.wikipedia.org/wiki/Advanced_Encryption_Standard">AES</a>.
/// **Attention:** JCA/JCE is buggy (creates a nonce of 12 on encryption but expects 16 bytes nonce on decryption,
/// etc.). Therefore you shall only use this with [BouncyCastle][SecurityProvider#BC].
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public class SymmetricCryptorConfigAes extends SymmetricCryptorConfig {

  /// [Cipher algorithm][CipherTransformation#getAlgorithm()] {@value}.
  public static final String ALGORITHM_AES = "AES";

  /// [CipherTransformation] for [AES][#ALGORITHM_AES] with [GCM][CipherTransformation#MODE_GCM] and
  /// [no padding][CipherTransformation#PADDING_NONE].
  public static final CipherTransformation TRANSFORMATION_AES_GCM_NOPADDING = new CipherTransformation(ALGORITHM_AES,
      CipherTransformation.MODE_GCM, CipherTransformation.PADDING_NONE);

  /// The constructor.
  ///
  /// @param mode the [cipher mode][CipherTransformation#getMode()].
  /// @param padding the [cipher padding][CipherTransformation#getPadding()].
  /// @param provider the [SecurityProvider].
  /// @param nonceSize the [nonce-size][#getNonceSize()].
  public SymmetricCryptorConfigAes(String mode, String padding, SecurityProvider provider, int nonceSize) {

    super(new CipherTransformation(ALGORITHM_AES, mode, padding), provider, nonceSize);
  }

  /// The constructor.
  ///
  /// @param provider the [SecurityProvider].
  public SymmetricCryptorConfigAes(SecurityProvider provider) {

    this(provider, 12);
  }

  /// The constructor.
  ///
  /// @param provider the [SecurityProvider].
  /// @param nonceSize the [nonce-size][#getNonceSize()].
  public SymmetricCryptorConfigAes(SecurityProvider provider, int nonceSize) {

    super(TRANSFORMATION_AES_GCM_NOPADDING, provider, nonceSize);
  }

}
