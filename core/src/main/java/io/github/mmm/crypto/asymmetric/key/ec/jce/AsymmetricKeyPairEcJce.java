package io.github.mmm.crypto.asymmetric.key.ec.jce;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import io.github.mmm.crypto.asymmetric.key.AsymmetricKeyPair;
import io.github.mmm.crypto.asymmetric.key.ec.AsymmetricKeyPairEc;

/// An implementation of [AsymmetricKeyPair] for [ECPrivateKey] and [ECPublicKey].
///
/// @since 1.0.0
public class AsymmetricKeyPairEcJce extends AsymmetricKeyPairEc<ECPrivateKey, ECPublicKey> {

  private static KeyFactory keyFactory;

  /// The constructor.
  ///
  /// @param privateKey the [private key][#getPrivateKey()].
  public AsymmetricKeyPairEcJce(ECPrivateKey privateKey) {

    super(privateKey, createPublicKey(privateKey));
  }

  /// The constructor.
  ///
  /// @param privateKey the [private key][#getPrivateKey()].
  /// @param publicKey the [public key][#getPrivateKey()].
  public AsymmetricKeyPairEcJce(ECPrivateKey privateKey, ECPublicKey publicKey) {

    super(privateKey, publicKey);
  }

  /// @param privateKey the [ECPrivateKey].
  /// @return the corresponding [ECPublicKey].
  public static ECPublicKey createPublicKey(ECPrivateKey privateKey) {

    BigInteger s = privateKey.getS();
    ECParameterSpec ecParameters = privateKey.getParams();
    // TODO
    ECPoint q = null; // ecParameters.getGenerator().multiply(s);
    return createPublicKey(q, ecParameters);
  }

  /// @param s the private key value [s][ECPrivateKey#getS()].
  /// @param ecParameters the [ECParameterSpec] representing the curve.
  /// @return the [ECPrivateKey].
  public static ECPrivateKey createPrivateKey(BigInteger s, ECParameterSpec ecParameters) {

    return createPrivateKey(new ECPrivateKeySpec(s, ecParameters));
  }

  /// @param keySpec the [ECPrivateKeySpec].
  /// @return the [ECPrivateKey].
  public static ECPrivateKey createPrivateKey(ECPrivateKeySpec keySpec) {

    return createPrivateKey(keySpec);
  }

  /// @param keySpec the [KeySpec].
  /// @return the [ECPrivateKey].
  private static ECPrivateKey createPrivateKey(KeySpec keySpec) {

    try {
      return (ECPrivateKey) getKeyFactory().generatePrivate(keySpec);
    } catch (InvalidKeySpecException e) {
      throw new IllegalArgumentException(e);
    }
  }

  /// @param data the compact data.
  /// @param ecParameters the [ECParameterSpec] representing the curve.
  /// @return the [ECPrivateKey].
  public static ECPrivateKey createPrivateKeyFromCompactData(byte[] data, ECParameterSpec ecParameters) {

    BigInteger s = new BigInteger(1, data);
    return createPrivateKey(s, ecParameters);
  }

  /// @param data the [encoded data][java.security.Key#getEncoded()].
  /// @return the [ECPrivateKey].
  public static ECPrivateKey createPrivateKeyFromEncodedData(byte[] data) {

    return createPrivateKey(new PKCS8EncodedKeySpec(data));
  }

  /// @param w the public key value [w][ECPublicKey#getW()].
  /// @param ecParameters the [ECParameterSpec] representing the curve.
  /// @return the [ECPublicKey].
  public static ECPublicKey createPublicKey(ECPoint w, ECParameterSpec ecParameters) {

    return createPublicKey(new ECPublicKeySpec(w, ecParameters));
  }

  /// @param keySpec the [ECPublicKeySpec].
  /// @return the [ECPublicKey].
  public static ECPublicKey createPublicKey(ECPublicKeySpec keySpec) {

    return createPublicKey(keySpec);
  }

  /// @param keySpec the [KeySpec].
  /// @return the [ECPublicKey].
  private static ECPublicKey createPublicKey(KeySpec keySpec) {

    try {
      return (ECPublicKey) getKeyFactory().generatePublic(keySpec);
    } catch (InvalidKeySpecException e) {
      throw new IllegalArgumentException(e);
    }
  }

  /// @param data the [compact data][io.github.mmm.crypto.CryptoBinaryFormat#FORMAT_COMPACT].
  /// @param ecParameters the [ECParameterSpec] representing the curve.
  /// @return the [ECPublicKey].
  public static ECPublicKey createPublicKeyFromCompactData(byte[] data, ECParameterSpec ecParameters) {

    // TODO
    ECPoint w = null; // ecParameters.getCurve().decodePoint(data);
    return createPublicKey(w, ecParameters);
  }

  /// @param data the [encoded data][java.security.Key#getEncoded()].
  /// @return the [ECPublicKey].
  public static ECPublicKey createPublicKeyFromEncodedData(byte[] data) {

    return createPublicKey(new X509EncodedKeySpec(data));
  }

  static KeyFactory getKeyFactory() {

    if (keyFactory == null) {
      try {
        keyFactory = KeyFactory.getInstance(ALGORITHM_EC);
      } catch (NoSuchAlgorithmException e) {
        throw new IllegalStateException(e);
      }
    }
    return keyFactory;
  }

}
