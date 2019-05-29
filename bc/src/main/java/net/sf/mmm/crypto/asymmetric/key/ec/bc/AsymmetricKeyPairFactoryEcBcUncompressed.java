package net.sf.mmm.crypto.asymmetric.key.ec.bc;

import net.sf.mmm.crypto.CryptoBinaryFormat;
import net.sf.mmm.crypto.asymmetric.key.AbstractAsymmetricKeyPairFactory;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Implementation of {@link AbstractAsymmetricKeyPairFactory} for EC using BouncyCastle in
 * {@link CryptoBinaryFormat#FORMAT_COMPACT compact format}.
 *
 * @since 1.0.0
 */
public class AsymmetricKeyPairFactoryEcBcUncompressed extends AsymmetricKeyPairFactoryEcBc {

  /**
   * The constructor.
   *
   * @param ecParameters the {@link ECParameterSpec}.
   */
  public AsymmetricKeyPairFactoryEcBcUncompressed(ECParameterSpec ecParameters) {

    super(ecParameters);
  }

  @Override
  public byte[] asData(BCECPublicKey publicKey) {

    return publicKey.getQ().getEncoded(false);
  }

  @Override
  public BCECPublicKey createPublicKey(byte[] data) {

    if (data.length > (this.byteLength * 2)) {
      return null;
    }
    ECPoint q = this.ecParameters.getCurve().decodePoint(data);
    return AsymmetricKeyPairEcBc.createPublicKey(q, this.ecParameters);
  }

}
