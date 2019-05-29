package net.sf.mmm.crypto.asymmetric.key.ec.bc;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import net.sf.mmm.crypto.asymmetric.key.AsymmetricKeyPair;
import net.sf.mmm.crypto.asymmetric.key.ec.AsymmetricKeyPairEc;
import net.sf.mmm.crypto.provider.BouncyCastle;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;

/**
 * An implementation of {@link AsymmetricKeyPair} for {@link BCECPrivateKey} and {@link BCECPublicKey}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class AsymmetricKeyPairEcBc extends AsymmetricKeyPairEc<BCECPrivateKey, BCECPublicKey> {

  private static KeyFactory keyFactory;

  /**
   * The constructor.
   *
   * @param privateKey the {@link #getPrivateKey() private key}.
   */
  public AsymmetricKeyPairEcBc(BCECPrivateKey privateKey) {

    super(privateKey, createPublicKey(privateKey));
  }

  /**
   * The constructor.
   *
   * @param privateKey the {@link #getPrivateKey() private key}.
   * @param publicKey the {@link #getPrivateKey() public key}.
   */
  public AsymmetricKeyPairEcBc(BCECPrivateKey privateKey, BCECPublicKey publicKey) {

    super(privateKey, publicKey);
  }

  static KeyFactory getKeyFactory() {

    if (keyFactory == null) {
      try {
        keyFactory = KeyFactory.getInstance(ALGORITHM_EC, BouncyCastle.getProvider());
      } catch (NoSuchAlgorithmException e) {
        throw new IllegalStateException(e);
      }
    }
    return keyFactory;
  }

  /**
   * @param s the private key value {@link BCECPrivateKey#getS() s}.
   * @param ecParameters the {@link ECParameterSpec} representing the curve.
   * @return the {@link BCECPrivateKey}.
   */
  public static BCECPrivateKey createPrivateKey(BigInteger s, ECParameterSpec ecParameters) {

    return createPrivateKey(new ECPrivateKeySpec(s, ecParameters));
  }

  /**
   * @param keySpec the {@link ECPrivateKeySpec}.
   * @return the {@link BCECPrivateKey}.
   */
  public static BCECPrivateKey createPrivateKey(ECPrivateKeySpec keySpec) {

    return new BCECPrivateKey(ALGORITHM_EC, keySpec, BouncyCastleProvider.CONFIGURATION);
  }

  /**
   * @param keySpec the {@link KeySpec}.
   * @return the {@link BCECPrivateKey}.
   */
  private static BCECPrivateKey createPrivateKey(KeySpec keySpec) {

    try {
      return (BCECPrivateKey) getKeyFactory().generatePrivate(keySpec);
    } catch (InvalidKeySpecException e) {
      throw new IllegalArgumentException(e);
    }
  }

  /**
   * @param data the {@link java.security.Key#getEncoded() encoded data}.
   * @return the {@link BCECPrivateKey}.
   */
  public static BCECPrivateKey createPrivateKeyFromEncodedData(byte[] data) {

    return createPrivateKey(new PKCS8EncodedKeySpec(data));
  }

  /**
   * @param privateKey the {@link BCECPrivateKey}.
   * @return the corresponding {@link BCECPublicKey}.
   */
  public static BCECPublicKey createPublicKey(BCECPrivateKey privateKey) {

    BigInteger s = privateKey.getS();
    ECParameterSpec ecParameters = privateKey.getParameters();
    ECPoint q = ecParameters.getG().multiply(s);
    return createPublicKey(q, ecParameters);
  }

  /**
   * @param q the public key value {@link ECPublicKey#getQ() q}.
   * @param ecParameters the {@link ECParameterSpec} representing the curve.
   * @return the {@link ECPublicKey}.
   */
  public static BCECPublicKey createPublicKey(ECPoint q, ECParameterSpec ecParameters) {

    return createPublicKey(new ECPublicKeySpec(q, ecParameters));
  }

  /**
   * @param keySpec the {@link ECPublicKeySpec}.
   * @return the {@link ECPublicKey}.
   */
  public static BCECPublicKey createPublicKey(ECPublicKeySpec keySpec) {

    return new BCECPublicKey(ALGORITHM_EC, keySpec, BouncyCastleProvider.CONFIGURATION);
  }

  /**
   * @param keySpec the {@link KeySpec}.
   * @return the {@link ECPublicKey}.
   */
  private static BCECPublicKey createPublicKey(KeySpec keySpec) {

    try {
      return (BCECPublicKey) getKeyFactory().generatePublic(keySpec);
    } catch (InvalidKeySpecException e) {
      throw new IllegalArgumentException(e);
    }
  }

  /**
   * @param data the {@link java.security.Key#getEncoded() encoded data}.
   * @return the {@link ECPublicKey}.
   */
  public static BCECPublicKey createPublicKeyFromEncodedData(byte[] data) {

    return createPublicKey(new X509EncodedKeySpec(data));
  }

}
