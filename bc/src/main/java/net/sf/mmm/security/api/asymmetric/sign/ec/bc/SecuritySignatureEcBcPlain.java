package net.sf.mmm.security.api.asymmetric.sign.ec.bc;

import java.math.BigInteger;

import net.sf.mmm.security.api.asymmetric.access.ec.bc.SecurityEllipticCurveBc;

/**
 * {@link SecuritySignatureEcBc} for a plain signature. This is one byte shorter than
 * {@link SecuritySignatureEcBcWithRecoveryId} but requires to also transmit the entire public key.
 *
 * @since 1.0.0
 */
public class SecuritySignatureEcBcPlain extends SecuritySignatureEcBc {

  /**
   * The constructor.
   *
   * @param curve the {@link #getCurve() elliptic curve}.
   * @param data the {@link #getData() binary data}.
   * @param r - see {@link #getR()}.
   * @param s - see {@link #getS()}.
   */
  public SecuritySignatureEcBcPlain(SecurityEllipticCurveBc curve, byte[] data, BigInteger r, BigInteger s) {

    super(curve, data, r, s);
  }

  /**
   * The constructor.
   *
   * @param curve the {@link #getCurve() elliptic curve}.
   * @param data the {@link #getData() binary data}.
   */
  public SecuritySignatureEcBcPlain(SecurityEllipticCurveBc curve, byte[] data) {

    super(curve, data);
  }

}
