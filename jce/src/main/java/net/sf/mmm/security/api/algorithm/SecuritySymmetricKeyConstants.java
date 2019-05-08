package net.sf.mmm.security.api.algorithm;

import net.sf.mmm.security.api.symmetric.key.SecuritySymmetricKeyFactory;

/**
 * Constants for {@link SecuritySymmetricKeyFactory} and related APIs.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecuritySymmetricKeyConstants {

  /** The {@link javax.crypto.SecretKeyFactory#getAlgorithm() key algorithm} {@value}. */
  String KEY_ALGORITHM_PBE_WITH_HMAC_SHA256_AND_AES128 = "PBEWithHmacSHA256AndAES_128";

  /** The {@link javax.crypto.SecretKeyFactory#getAlgorithm() key algorithm} {@value}. */
  String KEY_ALGORITHM_AES = "AES";

  /**
   * The {@link javax.crypto.SecretKeyFactory#getAlgorithm() key algorithm} {@value}.
   *
   * @deprecated This algorithm is very old and not suitable for todays security.
   */
  @Deprecated
  String KEY_ALGORITHM_DES = "DES";

  /**
   * The {@link javax.crypto.SecretKeyFactory#getAlgorithm() key algorithm} {@value} (Tripple-DES). This algorithm is
   * quite slow if implemented in software. Consider using {@link #KEY_ALGORITHM_AES} instead (at least for encryption
   * of longer payloads).
   */
  String KEY_ALGORITHM_DES_EDE = "DESede";

}
