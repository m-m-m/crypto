package net.sf.mmm.security.api.crypt.asymmetric;

import java.math.BigInteger;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmRsa;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyPair;
import net.sf.mmm.security.api.key.asymmetric.SecurityPrivateKey;
import net.sf.mmm.security.api.key.asymmetric.SecurityPublicKey;
import net.sf.mmm.security.api.key.asymmetric.generic.SecurityPrivateKeyGeneric;
import net.sf.mmm.security.api.key.asymmetric.generic.SecurityPublicKeyGeneric;
import net.sf.mmm.security.api.key.asymmetric.rsa.SecurityAsymmetricKeyConfigRsa;
import net.sf.mmm.security.api.key.asymmetric.rsa.SecurityAsymmetricKeyPairRsa;
import net.sf.mmm.security.api.sign.SecuritySignatureConfig;

/**
 * Direct builder for {@link SecurityAlgorithmRsa RSA}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public final class Rsa extends AbstractSecurityAsymmetricCryptorBuilder<Rsa> {

  private final SecurityAsymmetricCryptorConfigRsa cryptorConfig;

  private SecuritySignatureConfig signatureConfig;

  /**
   * The constructor.
   *
   * @param config the {@link SecurityAsymmetricCryptorConfigRsa}.
   */
  public Rsa(SecurityAsymmetricCryptorConfigRsa config) {

    super();
    this.cryptorConfig = config;
  }

  @Override
  protected SecurityAsymmetricCryptorConfigRsa getCryptorConfig() {

    return this.cryptorConfig;
  }

  @Override
  protected SecuritySignatureConfig getSignatureConfig() {

    if (this.signatureConfig == null) {
      this.signatureConfig = new SecuritySignatureConfig(getHashConfig(), SecurityAlgorithmRsa.ALGORITHM_RSA);
    }
    return this.signatureConfig;
  }

  /**
   * @param modulus is the {@link RSAKey#getModulus() modulus} (product of two large primes).
   * @param privateExponent the {@link RSAPrivateKey#getPrivateExponent() private exponent}.
   * @param publicExponent the {@link RSAPublicKey#getPublicExponent() public exponent}.
   * @return the {@link SecurityAsymmetricKeyPair}.
   */
  public SecurityAsymmetricKeyPairRsa createKeyPair(BigInteger modulus, BigInteger privateExponent, BigInteger publicExponent) {

    return SecurityAsymmetricKeyPairRsa.of(modulus, privateExponent, publicExponent);
  }

  /**
   * Simple access to (re)create fixed key pair for testing. Uses a fixed public exponent of 65537.
   *
   * @param modulus is the modulus (product of two large primes).
   * @param privateExponent the private key encryption exponent.
   * @return the {@link SecurityAsymmetricKeyPair}.
   */
  public SecurityAsymmetricKeyPair createKeyPair(String modulus, String privateExponent) {

    return SecurityAsymmetricKeyPairRsa.of(new BigInteger(modulus), new BigInteger(privateExponent));
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
    int expectedKeyLength = this.cryptorConfig.getKeyAlgorithmConfig().getKeyLength();
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
