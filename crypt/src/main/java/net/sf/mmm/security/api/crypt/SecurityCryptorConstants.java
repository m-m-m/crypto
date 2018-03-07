package net.sf.mmm.security.api.crypt;

/**
 * Constants for {@link SecurityCryptorFactory} and related APIs.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityCryptorConstants {

  /**
   * The {@link javax.crypto.Cipher#getAlgorithm() cryptographic algorithm} RSA (Ron Rivest, Adi Shamir and Leonard
   * Adleman) used by GPG and many others. For details see <a href="https://en.wikipedia.org/wiki/PKCS_1">PKCS #1</a>.
   */
  String CRYPTO_ALGORITHM_RSA = "RSA";

  /**
   * The {@link javax.crypto.Cipher#getAlgorithm() cryptographic algorithm} ECIES (Elliptic Curve Integrated Encryption
   * Scheme). For details see <a href="https://en.wikipedia.org/wiki/Elliptic_curve_cryptography">ECC</a>.
   */
  String CRYPTO_ALGORITHM_ECIES = "ECIES";

}
