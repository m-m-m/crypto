package net.sf.mmm.security.api.asymmetric.key.rsa;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmRsa;
import net.sf.mmm.security.api.asymmetric.key.AbstractSecurityAsymmetricKeyPair;
import net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyPair;

/**
 * An implementation of {@link SecurityAsymmetricKeyPair} for {@link net.sf.mmm.security.api.asymmetric.access.rsa.Rsa}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityAsymmetricKeyPairRsa extends AbstractSecurityAsymmetricKeyPair<RSAPrivateKey, RSAPublicKey> {

  /** The (default) public exponent for RSA key generation. */
  static BigInteger PUBLIC_EXPONENT = new BigInteger("65537");

  private static KeyFactory keyFactory;

  /**
   * The constructor.
   *
   * @param privateKey the {@link #getPrivateKey() private key}.
   * @param publicKey the {@link #getPrivateKey() public key}.
   */
  public SecurityAsymmetricKeyPairRsa(RSAPrivateKey privateKey, RSAPublicKey publicKey) {

    super(privateKey, publicKey);
  }

  /**
   * @param modulus is the {@link RSAKey#getModulus() modulus} (product of two large primes).
   * @param privateExponent the {@link RSAPrivateKey#getPrivateExponent() private exponent}.
   * @param publicExponent the {@link RSAPublicKey#getPublicExponent() public exponent}.
   * @return the {@link SecurityAsymmetricKeyPair}.
   */
  public static SecurityAsymmetricKeyPairRsa of(BigInteger modulus, BigInteger privateExponent, BigInteger publicExponent) {

    RSAPrivateKey privateKey = createPrivateKey(modulus, privateExponent);
    RSAPublicKey publicKey = createPublicKey(modulus, publicExponent);
    return new SecurityAsymmetricKeyPairRsa(privateKey, publicKey);
  }

  /**
   * @param modulus the {@link RSAPublicKey#getModulus() modulus}.
   * @return the {@link RSAPublicKey}.
   */
  public static RSAPublicKey createPublicKey(BigInteger modulus) {

    return createPublicKey(modulus, PUBLIC_EXPONENT);
  }

  /**
   * @param modulus the {@link RSAPublicKey#getModulus() modulus}.
   * @param publicExponent the {@link RSAPublicKey#getPublicExponent() public exponent}.
   * @return the {@link RSAPublicKey}.
   */
  public static RSAPublicKey createPublicKey(BigInteger modulus, BigInteger publicExponent) {

    RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, publicExponent);
    return createPublicKey(keySpec);
  }

  /**
   * @param keySpec the {@link RSAPublicKeySpec}.
   * @return the {@link RSAPublicKey}.
   */
  public static RSAPublicKey createPublicKey(RSAPublicKeySpec keySpec) {

    try {
      return (RSAPublicKey) getKeyFactory().generatePublic(keySpec);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * @param modulus is the {@link RSAKey#getModulus() modulus} (product of two large primes).
   * @param privateExponent the {@link RSAPrivateKey#getPrivateExponent() private exponent}.
   * @return the {@link SecurityAsymmetricKeyPair}.
   */
  public static SecurityAsymmetricKeyPairRsa of(BigInteger modulus, BigInteger privateExponent) {

    return of(modulus, privateExponent, PUBLIC_EXPONENT);
  }

  /**
   * Convenience method e.g. for test-data.
   *
   * @param modulus is the modulus (product of two large primes).
   * @param privateExponent the private key encryption exponent.
   * @return the {@link SecurityAsymmetricKeyPair}.
   */
  public static SecurityAsymmetricKeyPairRsa of(String modulus, String privateExponent) {

    return of(new BigInteger(modulus), new BigInteger(privateExponent), PUBLIC_EXPONENT);
  }

  /**
   * @param modulus the {@link RSAPrivateKey#getModulus() modulus}.
   * @param privateExponent the {@link RSAPrivateKey#getPrivateExponent() private exponent}.
   * @return the {@link RSAPrivateKey}.
   */
  public static RSAPrivateKey createPrivateKey(BigInteger modulus, BigInteger privateExponent) {

    RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(modulus, privateExponent);
    return createPrivateKey(keySpec);
  }

  /**
   * @param keySpec the {@link RSAPrivateKeySpec}.
   * @return the {@link RSAPrivateKey}.
   */
  public static RSAPrivateKey createPrivateKey(RSAPrivateKeySpec keySpec) {

    try {
      return (RSAPrivateKey) getKeyFactory().generatePrivate(keySpec);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  static KeyFactory getKeyFactory() {

    if (keyFactory == null) {
      try {
        keyFactory = KeyFactory.getInstance(SecurityAlgorithmRsa.ALGORITHM_RSA);
      } catch (NoSuchAlgorithmException e) {
        throw new IllegalStateException(e);
      }
    }
    return keyFactory;
  }

}
