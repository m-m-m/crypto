package net.sf.mmm.security.api.asymmetric.key.ec.jce;

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

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmEc;
import net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyPair;
import net.sf.mmm.security.api.asymmetric.key.ec.SecurityAsymmetricKeyPairEc;

/**
 * An implementation of {@link SecurityAsymmetricKeyPair} for {@link ECPrivateKey} and {@link ECPublicKey}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityAsymmetricKeyPairEcJce extends SecurityAsymmetricKeyPairEc<ECPrivateKey, ECPublicKey> {

  private static KeyFactory keyFactory;

  /**
   * The constructor.
   *
   * @param privateKey the {@link #getPrivateKey() private key}.
   */
  public SecurityAsymmetricKeyPairEcJce(ECPrivateKey privateKey) {

    super(privateKey, createPublicKey(privateKey));
  }

  /**
   * The constructor.
   *
   * @param privateKey the {@link #getPrivateKey() private key}.
   * @param publicKey the {@link #getPrivateKey() public key}.
   */
  public SecurityAsymmetricKeyPairEcJce(ECPrivateKey privateKey, ECPublicKey publicKey) {

    super(privateKey, publicKey);
  }

  /**
   * @param privateKey the {@link ECPrivateKey}.
   * @return the corresponding {@link ECPublicKey}.
   */
  public static ECPublicKey createPublicKey(ECPrivateKey privateKey) {

    BigInteger s = privateKey.getS();
    ECParameterSpec ecParameters = privateKey.getParams();
    // TODO
    ECPoint q = null; // ecParameters.getGenerator().multiply(s);
    return createPublicKey(q, ecParameters);
  }

  /**
   * @param s the private key value {@link ECPrivateKey#getS() s}.
   * @param ecParameters the {@link ECParameterSpec} representing the curve.
   * @return the {@link ECPrivateKey}.
   */
  public static ECPrivateKey createPrivateKey(BigInteger s, ECParameterSpec ecParameters) {

    return createPrivateKey(new ECPrivateKeySpec(s, ecParameters));
  }

  /**
   * @param keySpec the {@link ECPrivateKeySpec}.
   * @return the {@link ECPrivateKey}.
   */
  public static ECPrivateKey createPrivateKey(ECPrivateKeySpec keySpec) {

    return createPrivateKey(keySpec);
  }

  /**
   * @param keySpec the {@link KeySpec}.
   * @return the {@link ECPrivateKey}.
   */
  private static ECPrivateKey createPrivateKey(KeySpec keySpec) {

    try {
      return (ECPrivateKey) getKeyFactory().generatePrivate(keySpec);
    } catch (InvalidKeySpecException e) {
      throw new IllegalArgumentException(e);
    }
  }

  /**
   * @param data the compact data.
   * @param ecParameters the {@link ECParameterSpec} representing the curve.
   * @return the {@link ECPrivateKey}.
   */
  public static ECPrivateKey createPrivateKeyFromCompactData(byte[] data, ECParameterSpec ecParameters) {

    BigInteger s = new BigInteger(1, data);
    return createPrivateKey(s, ecParameters);
  }

  /**
   * @param data the {@link java.security.Key#getEncoded() encoded data}.
   * @return the {@link ECPrivateKey}.
   */
  public static ECPrivateKey createPrivateKeyFromEncodedData(byte[] data) {

    return createPrivateKey(new PKCS8EncodedKeySpec(data));
  }

  /**
   * @param w the public key value {@link ECPublicKey#getW() w}.
   * @param ecParameters the {@link ECParameterSpec} representing the curve.
   * @return the {@link ECPublicKey}.
   */
  public static ECPublicKey createPublicKey(ECPoint w, ECParameterSpec ecParameters) {

    return createPublicKey(new ECPublicKeySpec(w, ecParameters));
  }

  /**
   * @param keySpec the {@link ECPublicKeySpec}.
   * @return the {@link ECPublicKey}.
   */
  public static ECPublicKey createPublicKey(ECPublicKeySpec keySpec) {

    return createPublicKey(keySpec);
  }

  /**
   * @param keySpec the {@link KeySpec}.
   * @return the {@link ECPublicKey}.
   */
  private static ECPublicKey createPublicKey(KeySpec keySpec) {

    try {
      return (ECPublicKey) getKeyFactory().generatePublic(keySpec);
    } catch (InvalidKeySpecException e) {
      throw new IllegalArgumentException(e);
    }
  }

  /**
   * @param data the {@link net.sf.mmm.security.api.SecurityBinaryFormat#FORMAT_COMPACT compact data}.
   * @param ecParameters the {@link ECParameterSpec} representing the curve.
   * @return the {@link ECPublicKey}.
   */
  public static ECPublicKey createPublicKeyFromCompactData(byte[] data, ECParameterSpec ecParameters) {

    // TODO
    ECPoint w = null; // ecParameters.getCurve().decodePoint(data);
    return createPublicKey(w, ecParameters);
  }

  /**
   * @param data the {@link java.security.Key#getEncoded() encoded data}.
   * @return the {@link ECPublicKey}.
   */
  public static ECPublicKey createPublicKeyFromEncodedData(byte[] data) {

    return createPublicKey(new X509EncodedKeySpec(data));
  }

  static KeyFactory getKeyFactory() {

    if (keyFactory == null) {
      try {
        keyFactory = KeyFactory.getInstance(SecurityAlgorithmEc.ALGORITHM_EC);
      } catch (NoSuchAlgorithmException e) {
        throw new IllegalStateException(e);
      }
    }
    return keyFactory;
  }

}
