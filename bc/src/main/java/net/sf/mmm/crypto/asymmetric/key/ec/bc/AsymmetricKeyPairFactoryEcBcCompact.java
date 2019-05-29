package net.sf.mmm.crypto.asymmetric.key.ec.bc;

import net.sf.mmm.crypto.CryptoBinaryFormat;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Implementation of {@link AsymmetricKeyPairFactoryEcBc} in {@link CryptoBinaryFormat#FORMAT_COMPACT compact
 * format}.
 *
 * @since 1.0.0
 */
public class AsymmetricKeyPairFactoryEcBcCompact extends AsymmetricKeyPairFactoryEcBc {

  /**
   * The constructor.
   *
   * @param ecParameters the {@link ECParameterSpec}.
   */
  public AsymmetricKeyPairFactoryEcBcCompact(ECParameterSpec ecParameters) {

    super(ecParameters);
  }

  @Override
  public byte[] asData(BCECPublicKey publicKey) {

    return publicKey.getQ().getEncoded(true);
  }

  @Override
  public BCECPublicKey createPublicKey(byte[] data) {

    if (data.length > this.byteLength + 1) {
      return null;
    }
    ECPoint q = this.ecParameters.getCurve().decodePoint(data);
    return AsymmetricKeyPairEcBc.createPublicKey(q, this.ecParameters);
  }

}
