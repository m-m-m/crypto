package net.sf.mmm.crypto.asymmetric.key.ec.bc;

import java.math.BigInteger;
import java.security.KeyFactory;

import net.sf.mmm.crypto.asymmetric.access.ec.bc.CryptoEllipticCurveBc;
import net.sf.mmm.crypto.asymmetric.key.AbstractAsymmetricKeyPairFactory;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;

/**
 * Abstract base implementation of {@link AbstractAsymmetricKeyPairFactory} for EC using BouncyCastle.
 *
 * @since 1.0.0
 */
public abstract class AsymmetricKeyPairFactoryEcBc
    extends AbstractAsymmetricKeyPairFactory<BCECPrivateKey, BCECPublicKey, AsymmetricKeyPairEcBc> {

  /** @see CryptoEllipticCurveBc#getEcParameters() */
  protected final ECParameterSpec ecParameters;

  /** @see CryptoEllipticCurveBc#getByteLength() */
  protected final int byteLength;

  /**
   * The constructor.
   *
   * @param ecParameters the {@link ECParameterSpec}.
   */
  public AsymmetricKeyPairFactoryEcBc(ECParameterSpec ecParameters) {

    this(ecParameters, AsymmetricKeyPairEcBc.getKeyFactory());
  }

  /**
   * The constructor.
   *
   * @param ecParameters the {@link ECParameterSpec}.
   * @param keyFactory the {@link KeyFactory}.
   */
  public AsymmetricKeyPairFactoryEcBc(ECParameterSpec ecParameters, KeyFactory keyFactory) {

    super(keyFactory);
    this.ecParameters = ecParameters;
    this.byteLength = CryptoEllipticCurveBc.getByteLength(this.ecParameters);
  }

  @Override
  public byte[] asData(BCECPrivateKey privateKey) {

    byte[] data = privateKey.getD().toByteArray();
    if (data[0] == 0) {
      // ugly waste but Java does not seem to offer another way to do it
      byte[] compactData = new byte[data.length - 1];
      System.arraycopy(data, 1, compactData, 0, compactData.length);
      data = compactData;
    }
    return data;
  }

  @Override
  public BCECPrivateKey createPrivateKey(byte[] data) {

    if (data.length > this.byteLength) {
      return null;
    }
    BigInteger s = new BigInteger(1, data);
    return AsymmetricKeyPairEcBc.createPrivateKey(s, this.ecParameters);
  }

  @Override
  public byte[] asData(AsymmetricKeyPairEcBc keyPair) {

    return asData(keyPair.getPrivateKey());
  }

  @Override
  public AsymmetricKeyPairEcBc createKeyPair(byte[] data) {

    BCECPrivateKey privateKey = createPrivateKey(data);
    return new AsymmetricKeyPairEcBc(privateKey);
  }

  @Override
  public AsymmetricKeyPairEcBc createKeyPair(BCECPrivateKey privateKey, BCECPublicKey publicKey) {

    return new AsymmetricKeyPairEcBc(privateKey, publicKey);
  }

}
