package net.sf.mmm.security.api.crypt.asymmetric;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmRsa;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyConfigRsa;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyPair;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyPairGeneric;
import net.sf.mmm.security.api.key.asymmetric.SecurityPrivateKey;
import net.sf.mmm.security.api.key.asymmetric.SecurityPrivateKeyGeneric;
import net.sf.mmm.security.api.key.asymmetric.SecurityPublicKey;
import net.sf.mmm.security.api.key.asymmetric.SecurityPublicKeyGeneric;

/**
 * Direct builder for {@link SecurityAlgorithmRsa RSA}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public final class Rsa extends AbstractSecurityAsymmetricCryptorBuilderBidirectional<Rsa> {

  private final SecurityAsymmetricCryptorConfigRsa config;

  /** The (default) public exponent for RSA key generation. */
  private static BigInteger PUBLIC_EXPONENT = new BigInteger("65537");

  /**
   * The constructor.
   *
   * @param config the {@link SecurityAsymmetricCryptorConfigRsa}.
   */
  public Rsa(SecurityAsymmetricCryptorConfigRsa config) {

    super();
    this.config = config;
  }

  @Override
  protected SecurityAsymmetricCryptorConfigRsa getCryptorConfig() {

    return this.config;
  }

  /**
   * @param modulus is the {@link RSAKey#getModulus() modulus} (product of two large primes).
   * @param privateExponent the {@link RSAPrivateKey#getPrivateExponent() private exponent}.
   * @param publicExponent the {@link RSAPublicKey#getPublicExponent() public exponent}.
   * @return the {@link SecurityAsymmetricKeyPair}.
   */
  public SecurityAsymmetricKeyPair createKeyPair(BigInteger modulus, BigInteger privateExponent, BigInteger publicExponent) {

    try {
      KeyFactory factory = KeyFactory.getInstance(SecurityAlgorithmRsa.ALGORITHM_RSA);
      RSAPrivateKey privateKey = (RSAPrivateKey) factory.generatePrivate(new RSAPrivateKeySpec(modulus, privateExponent));
      RSAPublicKey publicKey = (RSAPublicKey) factory.generatePublic(new RSAPublicKeySpec(modulus, publicExponent));
      return new SecurityAsymmetricKeyPairGeneric(wrapPrivateKey(privateKey), wrapPublicKey(publicKey));
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * Simple access to (re)create fixed key pair for testing. Uses a fixed public exponent of 65537.
   *
   * @param modulus is the modulus (product of two large primes).
   * @param privateExponent the private key encryption exponent.
   * @return the {@link SecurityAsymmetricKeyPair}.
   */
  public SecurityAsymmetricKeyPair createKeyPair(String modulus, String privateExponent) {

    return createKeyPair(new BigInteger(modulus), new BigInteger(privateExponent), PUBLIC_EXPONENT);
  }

  /**
   * @param privateKey the {@link RSAPrivateKey} to wrap.
   * @return the wrapped {@link SecurityPrivateKey}.
   */
  public SecurityPrivateKey wrapPrivateKey(RSAPrivateKey privateKey) {

    verifyKeyBitLength(privateKey);
    return new SecurityPrivateKeyGeneric(privateKey);
  }

  /**
   * @param publicKey the {@link RSAPrivateKey} to wrap.
   * @return the wrapped {@link SecurityPrivateKey}.
   */
  public SecurityPublicKey wrapPublicKey(RSAPublicKey publicKey) {

    verifyKeyBitLength(publicKey);
    return new SecurityPublicKeyGeneric(publicKey);
  }

  private void verifyKeyBitLength(RSAKey key) {

    int actualKeyLength = key.getModulus().bitLength();
    int expectedKeyLength = this.config.getKeyAlgorithmConfig().getKeyLength();
    if (actualKeyLength != expectedKeyLength) {
      throw new IllegalArgumentException("Invalid key length " + actualKeyLength + " - required to be " + expectedKeyLength + ".");
    }
  }

  /**
   * @param keyLength the {@link net.sf.mmm.security.api.key.SecurityKeyConfig#getKeyLength() key length} in bits.
   * @return the according {@link Rsa} instance.
   */
  public static Rsa keyLength(int keyLength) {

    return new Rsa(new SecurityAsymmetricCryptorConfigRsa(new SecurityAsymmetricKeyConfigRsa(keyLength)));
  }

  /**
   * @return the result of {@link #keyLength(int) keyLength}(4096).
   */
  public static Rsa keyLength4096() {

    return new Rsa(SecurityAsymmetricCryptorConfigRsa.RSA_4096);
  }

}
