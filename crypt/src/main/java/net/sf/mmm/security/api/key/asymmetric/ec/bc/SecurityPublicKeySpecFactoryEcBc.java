package net.sf.mmm.security.api.key.asymmetric.ec.bc;

import java.security.spec.KeySpec;

import net.sf.mmm.security.api.key.asymmetric.SecurityPublicKey;
import net.sf.mmm.security.api.key.asymmetric.SecurityPublicKeySpecFactory;

import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Implementation of {@link SecurityPublicKeySpecFactory} for {@link SecurityPrivateKeyEcBc}.
 *
 * @since 1.0.0
 */
public class SecurityPublicKeySpecFactoryEcBc extends SecurityAsymmetricKeySpecFactoryEcBc<SecurityPublicKey>
    implements SecurityPublicKeySpecFactory {

  /**
   * The constructor.
   *
   * @param ecParameters the {@link ECParameterSpec} defining the elliptic curve.
   */
  public SecurityPublicKeySpecFactoryEcBc(ECParameterSpec ecParameters) {

    super(ecParameters);
  }

  @Override
  public KeySpec createKeySpec(byte[] publicKey) {

    ECCurve curve = this.ecParameters.getCurve();
    ECPoint q = curve.decodePoint(publicKey);
    return new ECPublicKeySpec(q, this.ecParameters);
  }

}
