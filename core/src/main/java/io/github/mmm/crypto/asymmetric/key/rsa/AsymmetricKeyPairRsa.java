package io.github.mmm.crypto.asymmetric.key.rsa;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import io.github.mmm.crypto.asymmetric.key.AbstractAsymmetricKeyPair;
import io.github.mmm.crypto.asymmetric.key.AsymmetricKeyPair;

/// An implementation of [AsymmetricKeyPair] for [io.github.mmm.crypto.asymmetric.access.rsa.Rsa].
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public class AsymmetricKeyPairRsa extends AbstractAsymmetricKeyPair<RSAPrivateKey, RSAPublicKey> {

  /// The [algorithm][io.github.mmm.crypto.algorithm.CryptoAlgorithm#getAlgorithm()] name {@value}.
  public static final String ALGORITHM_RSA = "RSA";

  /// The (default) public exponent for RSA key generation.
  static BigInteger PUBLIC_EXPONENT = new BigInteger("65537");

  private static KeyFactory keyFactory;

  /// The constructor.
  ///
  /// @param privateKey the [private key][#getPrivateKey()].
  /// @param publicKey the [public key][#getPrivateKey()].
  public AsymmetricKeyPairRsa(RSAPrivateKey privateKey, RSAPublicKey publicKey) {

    super(privateKey, publicKey);
  }

  /// @param modulus is the [modulus][RSAKey#getModulus()] (product of two large primes).
  /// @param privateExponent the [private exponent][RSAPrivateKey#getPrivateExponent()].
  /// @param publicExponent the [public exponent][RSAPublicKey#getPublicExponent()].
  /// @return the [AsymmetricKeyPair].
  public static AsymmetricKeyPairRsa of(BigInteger modulus, BigInteger privateExponent, BigInteger publicExponent) {

    RSAPrivateKey privateKey = createPrivateKey(modulus, privateExponent);
    RSAPublicKey publicKey = createPublicKey(modulus, publicExponent);
    return new AsymmetricKeyPairRsa(privateKey, publicKey);
  }

  /// @param modulus the [modulus][RSAPublicKey#getModulus()].
  /// @return the [RSAPublicKey].
  public static RSAPublicKey createPublicKey(BigInteger modulus) {

    return createPublicKey(modulus, PUBLIC_EXPONENT);
  }

  /// @param modulus the [modulus][RSAPublicKey#getModulus()].
  /// @param publicExponent the [public exponent][RSAPublicKey#getPublicExponent()].
  /// @return the [RSAPublicKey].
  public static RSAPublicKey createPublicKey(BigInteger modulus, BigInteger publicExponent) {

    RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, publicExponent);
    return createPublicKey(keySpec);
  }

  /// @param keySpec the [RSAPublicKeySpec].
  /// @return the [RSAPublicKey].
  public static RSAPublicKey createPublicKey(RSAPublicKeySpec keySpec) {

    try {
      return (RSAPublicKey) getKeyFactory().generatePublic(keySpec);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  /// @param modulus is the [modulus][RSAKey#getModulus()] (product of two large primes).
  /// @param privateExponent the [private exponent][RSAPrivateKey#getPrivateExponent()].
  /// @return the [AsymmetricKeyPair].
  public static AsymmetricKeyPairRsa of(BigInteger modulus, BigInteger privateExponent) {

    return of(modulus, privateExponent, PUBLIC_EXPONENT);
  }

  /// Convenience method e.g. for test-data.
  ///
  /// @param modulus is the modulus (product of two large primes).
  /// @param privateExponent the private key encryption exponent.
  /// @return the [AsymmetricKeyPair].
  public static AsymmetricKeyPairRsa of(String modulus, String privateExponent) {

    return of(new BigInteger(modulus), new BigInteger(privateExponent), PUBLIC_EXPONENT);
  }

  /// @param modulus the [modulus][RSAPrivateKey#getModulus()].
  /// @param privateExponent the [private exponent][RSAPrivateKey#getPrivateExponent()].
  /// @return the [RSAPrivateKey].
  public static RSAPrivateKey createPrivateKey(BigInteger modulus, BigInteger privateExponent) {

    RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(modulus, privateExponent);
    return createPrivateKey(keySpec);
  }

  /// @param keySpec the [RSAPrivateKeySpec].
  /// @return the [RSAPrivateKey].
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
        keyFactory = KeyFactory.getInstance(ALGORITHM_RSA);
      } catch (NoSuchAlgorithmException e) {
        throw new IllegalStateException(e);
      }
    }
    return keyFactory;
  }

}
