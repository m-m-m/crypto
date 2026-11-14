package io.github.mmm.crypto.asymmetric.sign.ec.bc;

import java.math.BigInteger;

import io.github.mmm.crypto.asymmetric.access.ec.bc.CryptoEllipticCurveBc;

/// [SignatureEcBc] for a plain signature. This is one byte shorter than
/// [SignatureEcBcWithRecoveryId] but requires to also transmit the entire public key.
///
/// @since 1.0.0
public class SignatureEcBcPlain extends SignatureEcBc {

  /// The constructor.
  ///
  /// @param curve the [elliptic curve][#getCurve()].
  /// @param data the [binary data][#getData()].
  /// @param r - see [#getR()].
  /// @param s - see [#getS()].
  public SignatureEcBcPlain(CryptoEllipticCurveBc curve, byte[] data, BigInteger r, BigInteger s) {

    super(curve, data, r, s);
  }

  /// The constructor.
  ///
  /// @param curve the [elliptic curve][#getCurve()].
  /// @param data the [binary data][#getData()].
  public SignatureEcBcPlain(CryptoEllipticCurveBc curve, byte[] data) {

    super(curve, data);
  }

}
