package net.sf.mmm.security.api.asymmetric.sign.ec.bc;

import java.math.BigInteger;

import net.sf.mmm.security.api.asymmetric.access.ec.bc.SecurityEllipticCurveBc;
import net.sf.mmm.security.api.asymmetric.sign.SecuritySignatureFactory;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;

/**
 * Implementation of {@link SecuritySignatureFactory} for {@link SecuritySignatureEcBcPlain}.
 *
 * @since 1.0.0
 */
public class SecuritySignatureFactoryEcBcPlain extends SecuritySignatureFactoryEcBc<SecuritySignatureEcBcPlain> {

  /**
   * The constructor.
   *
   * @param curve the {@link SecurityEllipticCurveBc elliptic curve}.
   */
  public SecuritySignatureFactoryEcBcPlain(SecurityEllipticCurveBc curve) {

    super(curve);
  }

  @Override
  public SecuritySignatureEcBcPlain createSignature(byte[] data) {

    return new SecuritySignatureEcBcPlain(this.curve, data);
  }

  @Override
  public SecuritySignatureEcBcPlain create(BigInteger r, BigInteger s, byte[] message, BCECPublicKey publicKey) {

    byte[] data = SecuritySignatureEcBcPlain.createData(0, r, s);
    return new SecuritySignatureEcBcPlain(this.curve, data, r, s);
  }

}
