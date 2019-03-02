package net.sf.mmm.security.api.key.asymmetric.ec.bc;

import java.math.BigInteger;
import java.security.spec.KeySpec;

import net.sf.mmm.security.api.key.asymmetric.SecurityPrivateKey;
import net.sf.mmm.security.api.key.asymmetric.SecurityPrivateKeySpecFactory;

import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;

/**
 * Implementation of {@link SecurityPrivateKeySpecFactory} for {@link SecurityPrivateKeyEcBc}.
 *
 * @since 1.0.0
 */
public class SecurityPrivateKeySpecFactoryEcBc extends SecurityAsymmetricKeySpecFactoryEcBc<SecurityPrivateKey>
    implements SecurityPrivateKeySpecFactory {

  /**
   * The constructor.
   *
   * @param ecParameters the {@link ECParameterSpec} defining the elliptic curve.
   */
  public SecurityPrivateKeySpecFactoryEcBc(ECParameterSpec ecParameters) {

    super(ecParameters);
  }

  @Override
  public KeySpec createKeySpec(byte[] privateKey) {

    BigInteger s = new BigInteger(1, privateKey);
    return new ECPrivateKeySpec(s, this.ecParameters);
  }

}
