package net.sf.mmm.crypto.asymmetric.key.ec.jce;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

import net.sf.mmm.crypto.asymmetric.key.AbstractAsymmetricKeyPairFactory;
import net.sf.mmm.crypto.asymmetric.key.AsymmetricKeyPairFactory;

/**
 * Implementation of {@link AsymmetricKeyPairFactory} for {@link AsymmetricKeyPairEcJce}.
 *
 * @since 1.0.0
 */
public class AsymmetricKeyPairFactoryEcJce
    extends AbstractAsymmetricKeyPairFactory<ECPrivateKey, ECPublicKey, AsymmetricKeyPairEcJce> {

  private final ECParameterSpec ecParameters;

  /**
   * The constructor.
   *
   * @param ecParameters the {@link ECParameterSpec}.
   */
  public AsymmetricKeyPairFactoryEcJce(ECParameterSpec ecParameters) {

    super(AsymmetricKeyPairEcJce.getKeyFactory());
    this.ecParameters = ecParameters;
  }

  @Override
  public byte[] asData(ECPrivateKey privateKey) {

    byte[] data = privateKey.getS().toByteArray();
    if (data[0] == 0) {
      // ugly waste but Java does not seem to offer another way to do it
      byte[] compactData = new byte[data.length - 1];
      System.arraycopy(data, 1, compactData, 0, compactData.length);
      data = compactData;
    }
    return data;
  }

  @Override
  public ECPrivateKey createPrivateKey(byte[] data) {

    BigInteger s = new BigInteger(1, data);
    return AsymmetricKeyPairEcJce.createPrivateKey(s, this.ecParameters);
  }

  @Override
  public byte[] asData(ECPublicKey publicKey) {

    // TODO
    // publicKey.getW().getEncoded(true);
    return null;
  }

  @Override
  public ECPublicKey createPublicKey(byte[] data) {

    // TODO
    ECPoint w = null;
    return AsymmetricKeyPairEcJce.createPublicKey(w, this.ecParameters);
  }

  @Override
  public byte[] asData(AsymmetricKeyPairEcJce keyPair) {

    return asData(keyPair.getPrivateKey());
  }

  @Override
  public AsymmetricKeyPairEcJce createKeyPair(byte[] data) {

    ECPrivateKey privateKey = createPrivateKey(data);
    return new AsymmetricKeyPairEcJce(privateKey);
  }

  @Override
  public AsymmetricKeyPairEcJce createKeyPair(ECPrivateKey privateKey, ECPublicKey publicKey) {

    return new AsymmetricKeyPairEcJce(privateKey, publicKey);
  }

}
