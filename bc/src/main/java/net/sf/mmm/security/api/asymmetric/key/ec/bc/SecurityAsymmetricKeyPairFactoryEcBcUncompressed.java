package net.sf.mmm.security.api.asymmetric.key.ec.bc;

import net.sf.mmm.security.api.SecurityBinaryFormat;
import net.sf.mmm.security.api.asymmetric.key.AbstractSecurityAsymmetricKeyPairFactory;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Implementation of {@link AbstractSecurityAsymmetricKeyPairFactory} for EC using BouncyCastle in
 * {@link SecurityBinaryFormat#FORMAT_COMPACT compact format}.
 *
 * @since 1.0.0
 */
public class SecurityAsymmetricKeyPairFactoryEcBcUncompressed extends SecurityAsymmetricKeyPairFactoryEcBc {

  /**
   * The constructor.
   *
   * @param ecParameters the {@link ECParameterSpec}.
   */
  public SecurityAsymmetricKeyPairFactoryEcBcUncompressed(ECParameterSpec ecParameters) {

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
    return SecurityAsymmetricKeyPairEcBc.createPublicKey(q, this.ecParameters);
  }

}
