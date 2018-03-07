package net.sf.mmm.security.api.key.asymmetric;

/**
 * Constants for {@link SecurityAsymmetricKeyFactory} and related APIs.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityAsymmetricKeyConstants {

  /**
   * The {@link java.security.KeyFactory#getAlgorithm() key algorithm} EC (Elliptic Curves). For details see
   * <a href="https://en.wikipedia.org/wiki/Elliptic_curve_cryptography">ECC</a>.
   */
  String KEY_ALGORITHM_EC = "EC";

  /**
   * The {@link java.security.KeyFactory#getAlgorithm() key algorithm}
   * {@link net.sf.mmm.security.api.crypt.SecurityCryptorFactory#CRYPTO_ALGORITHM_RSA RSA}.
   */
  String KEY_ALGORITHM_RSA = "RSA";

  /**
   * The {@link java.security.KeyFactory#getAlgorithm() key algorithm}
   * {@link net.sf.mmm.security.api.crypt.SecurityCryptorFactory#CRYPTO_ALGORITHM_RSA RSA}.
   */
  String KEY_ALGORITHM_AES = "AES";

  /** The {@link java.security.Key#getFormat() key format} {@value}. */
  String KEY_FORMAT_X509 = "X.509";

  /** The {@link java.security.Key#getFormat() key format} {@value}. */
  String KEY_FORMAT_PKCS_8 = "PKCS#8";

}
