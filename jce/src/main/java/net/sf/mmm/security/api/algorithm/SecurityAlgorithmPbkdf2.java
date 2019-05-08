package net.sf.mmm.security.api.algorithm;

/**
 * The {@link SecurityAlgorithm} PBKDF2 (Password-Based Key Derivation Function 2) from <em>PKCS #5 v2.0</em>. For
 * details see <a href="https://en.wikipedia.org/wiki/PBKDF2">PBKDF2</a>.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityAlgorithmPbkdf2 extends SecurityAlgorithm {

  /** The {@link #getAlgorithm() algorithm} name {@value}. */
  String ALGORITHM_PBKDF2_WITH_HMAC_SHA224 = "PBKDF2WithHmacSHA224";

  /** The {@link #getAlgorithm() algorithm} name {@value}. */
  String ALGORITHM_PBKDF2_WITH_HMAC_SHA256 = "PBKDF2WithHmacSHA256";

  /** The {@link #getAlgorithm() algorithm} name {@value}. */
  String ALGORITHM_PBKDF2_WITH_HMAC_SHA384 = "PBKDF2WithHmacSHA384";

  /** The {@link #getAlgorithm() algorithm} name {@value}. */
  String ALGORITHM_PBKDF2_WITH_HMAC_SHA512 = "PBKDF2WithHmacSHA512";

}
