package io.github.mmm.crypto.asymmetric.key.ec.bc;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

import io.github.mmm.crypto.CryptoBinaryFormat;

/// Implementation of [AsymmetricKeyPairFactoryEcBc] in [compact format][CryptoBinaryFormat#FORMAT_COMPACT].
///
/// @since 1.0.0
public class AsymmetricKeyPairFactoryEcBcCompact extends AsymmetricKeyPairFactoryEcBc {

  /// The constructor.
  ///
  /// @param ecParameters the [ECParameterSpec].
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
