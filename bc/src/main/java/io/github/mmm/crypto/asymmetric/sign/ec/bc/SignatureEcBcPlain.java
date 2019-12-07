package io.github.mmm.crypto.asymmetric.sign.ec.bc;

import java.math.BigInteger;

import io.github.mmm.crypto.asymmetric.access.ec.bc.CryptoEllipticCurveBc;

/**
 * {@link SignatureEcBc} for a plain signature. This is one byte shorter than
 * {@link SignatureEcBcWithRecoveryId} but requires to also transmit the entire public key.
 *
 * @since 1.0.0
 */
public class SignatureEcBcPlain extends SignatureEcBc {

  /**
   * The constructor.
   *
   * @param curve the {@link #getCurve() elliptic curve}.
   * @param data the {@link #getData() binary data}.
   * @param r - see {@link #getR()}.
   * @param s - see {@link #getS()}.
   */
  public SignatureEcBcPlain(CryptoEllipticCurveBc curve, byte[] data, BigInteger r, BigInteger s) {

    super(curve, data, r, s);
  }

  /**
   * The constructor.
   *
   * @param curve the {@link #getCurve() elliptic curve}.
   * @param data the {@link #getData() binary data}.
   */
  public SignatureEcBcPlain(CryptoEllipticCurveBc curve, byte[] data) {

    super(curve, data);
  }

}
