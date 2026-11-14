package io.github.mmm.crypto.asymmetric.sign.ec.bc;

import java.math.BigInteger;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;

import io.github.mmm.crypto.asymmetric.access.ec.bc.CryptoEllipticCurveBc;
import io.github.mmm.crypto.asymmetric.sign.SignatureWithPublicKeyRecovery;

/// [SignatureEcBc] with an extra byte for the [recovery ID][#getRecoveryId()]. Allows to
/// [recover][#recoverPublicKey(byte\[\])] the [public key][BCECPublicKey]. This enables to transfer only a compact hash
/// of the public key to save capacity. E.g. BitCoin uses this to transmit a BitCoin Address instead of the actual public
/// key.
///
/// @since 1.0.0
public class SignatureEcBcWithRecoveryId extends SignatureEcBc implements SignatureWithPublicKeyRecovery {

  /// [recovery offset][#getRecoveryOffset()] used for BitCoin. Nobody knows why this magic number was chosen.
  public static final byte BITCOIN_RECOVERY_OFFSET = 27;

  /// Additional [recovery offset][#getRecoveryOffset()] used for BitCoin for compressed public key.
  public static final byte BITCOIN_COMPRESSED_OFFSET = 4;

  private static final int HEAD = 1;

  private final byte recoveryOffset;

  /// The constructor.
  ///
  /// @param curve the [elliptic curve][#getCurve()].
  /// @param data the [binary data][#getData()].
  /// @param r - see [#getR()].
  /// @param s - see [#getS()].
  /// @param recoveryOffset the [recovery offset][#getRecoveryOffset()].
  protected SignatureEcBcWithRecoveryId(CryptoEllipticCurveBc curve, byte[] data, BigInteger r, BigInteger s,
      byte recoveryOffset) {

    super(curve, data, r, s);
    this.recoveryOffset = recoveryOffset;
  }

  /// The constructor.
  ///
  /// @param curve the [elliptic curve][#getCurve()].
  /// @param data the [binary data][#getData()].
  /// @param recoveryOffset the [recovery offset][#getRecoveryOffset()].
  public SignatureEcBcWithRecoveryId(CryptoEllipticCurveBc curve, byte[] data, byte recoveryOffset) {

    super(curve, data);
    this.recoveryOffset = recoveryOffset;
  }

  @Override
  protected int getHead() {

    return HEAD;
  }

  /// @return the recovery ID containing the [recovery index][#getRecoveryIndex()] and
  ///         [compression][#isCompressed()] information.
  public byte getRecoveryId() {

    return this.data[0];
  }

  /// @return the index to [recover the public key][#recoverPublicKey(byte\[\])] from the signature. It is a value in
  ///         the range from `0` to `3`.
  public byte getRecoveryIndex() {

    int recoveryIndex = this.data[0] - this.recoveryOffset;
    recoveryIndex = recoveryIndex % 4;
    return (byte) recoveryIndex;
  }

  /// @return the offset to add to the [recovery index][#getRecoveryIndex()] for building the
  ///         [recovery ID][#getRecoveryId()].
  protected byte getRecoveryOffset() {

    return this.recoveryOffset;
  }

  /// @return `true` if public key was compressed, `false` otherwise.
  public boolean isCompressed() {

    return (this.data[0] - this.recoveryOffset) >= BITCOIN_COMPRESSED_OFFSET;
  }

  /// @param message the payload (typically hash of message) that was signed when this signature was created.
  /// @return the recovered public key.
  @Override
  public BCECPublicKey recoverPublicKey(byte[] message) {

    BCECPublicKey publicKey = recoverPublicKey(message, getRecoveryIndex());
    if (publicKey != null) {
      return publicKey;
    }
    throw new IllegalArgumentException(
        "Can not recover public key from signature. Most probably you did not provide the same playload as when creating the signature.");
  }

  /// @param curve the [elliptic curve][#getCurve()].
  /// @param r the value [r][#getR()].
  /// @param s the value [s][#getS()].
  /// @param message the signed message (hash).
  /// @param publicKey the [BCECPublicKey] that was used to sign the message.
  /// @param recoveryOffset the [recovery offset][#getRecoveryOffset()].
  /// @return the signature.
  public static SignatureEcBcWithRecoveryId of(CryptoEllipticCurveBc curve, BigInteger r, BigInteger s, byte[] message,
      BCECPublicKey publicKey, byte recoveryOffset) {

    BigInteger sCanonical = s;
    BigInteger halfN = curve.getHalfN();
    if (halfN != null) {
      if (s.compareTo(halfN) > 0) {
        sCanonical = curve.getEcParameters().getN().subtract(s);
      }
    }
    byte[] data = createData(HEAD, r, sCanonical);
    byte recoveryIndex = calculateRecoveryIndex(message, curve, r, sCanonical, publicKey);
    int recoveryId = recoveryIndex + recoveryOffset;
    data[0] = (byte) recoveryId;
    return new SignatureEcBcWithRecoveryId(curve, data, r, sCanonical, recoveryOffset);
  }

}
