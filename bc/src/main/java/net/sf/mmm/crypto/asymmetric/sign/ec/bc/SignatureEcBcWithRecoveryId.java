package net.sf.mmm.crypto.asymmetric.sign.ec.bc;

import java.math.BigInteger;

import net.sf.mmm.crypto.asymmetric.access.ec.bc.CryptoEllipticCurveBc;
import net.sf.mmm.crypto.asymmetric.sign.SignatureWithPublicKeyRecovery;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;

/**
 * {@link SignatureEcBc} with an extra byte for the {@link #getRecoveryId() recovery ID}. Allows to
 * {@link #recoverPublicKey(byte[]) recover} the {@link BCECPublicKey public key}. This enables to transfer only a
 * compact hash of the public key to save capacity. E.g. BitCoin uses this to transmit a BitCoin Address instead of the
 * actual public key.
 *
 * @since 1.0.0
 */
public class SignatureEcBcWithRecoveryId extends SignatureEcBc implements SignatureWithPublicKeyRecovery {

  /** {@link #getRecoveryOffset() recovery offset} used for BitCoin. Nobody knows why this magic number was chosen. */
  public static final byte BITCOIN_RECOVERY_OFFSET = 27;

  /** Additional {@link #getRecoveryOffset() recovery offset} used for BitCoin for compressed public key. */
  public static final byte BITCOIN_COMPRESSED_OFFSET = 4;

  private static final int HEAD = 1;

  private final byte recoveryOffset;

  /**
   * The constructor.
   *
   * @param curve the {@link #getCurve() elliptic curve}.
   * @param data the {@link #getData() binary data}.
   * @param r - see {@link #getR()}.
   * @param s - see {@link #getS()}.
   * @param recoveryOffset the {@link #getRecoveryOffset() recovery offset}.
   */
  protected SignatureEcBcWithRecoveryId(CryptoEllipticCurveBc curve, byte[] data, BigInteger r, BigInteger s,
      byte recoveryOffset) {

    super(curve, data, r, s);
    this.recoveryOffset = recoveryOffset;
  }

  /**
   * The constructor.
   *
   * @param curve the {@link #getCurve() elliptic curve}.
   * @param data the {@link #getData() binary data}.
   * @param recoveryOffset the {@link #getRecoveryOffset() recovery offset}.
   */
  public SignatureEcBcWithRecoveryId(CryptoEllipticCurveBc curve, byte[] data, byte recoveryOffset) {

    super(curve, data);
    this.recoveryOffset = recoveryOffset;
  }

  @Override
  protected int getHead() {

    return HEAD;
  }

  /**
   * @return the recovery ID containing the {@link #getRecoveryIndex() recovery index} and {@link #isCompressed()
   *         compression} information.
   */
  public byte getRecoveryId() {

    return this.data[0];
  }

  /**
   * @return the index to {@link #recoverPublicKey(byte[]) recover the public key} from the signature. It is a value in
   *         the range from {@code 0} to {@code 3}.
   */
  public byte getRecoveryIndex() {

    int recoveryIndex = this.data[0] - this.recoveryOffset;
    recoveryIndex = recoveryIndex % 4;
    return (byte) recoveryIndex;
  }

  /**
   * @return the offset to add to the {@link #getRecoveryIndex() recovery index} for building the
   *         {@link #getRecoveryId() recovery ID}.
   */
  protected byte getRecoveryOffset() {

    return this.recoveryOffset;
  }

  /**
   * @return {@code true} if public key was compressed, {@code false} otherwise.
   */
  public boolean isCompressed() {

    return (this.data[0] - this.recoveryOffset) >= BITCOIN_COMPRESSED_OFFSET;
  }

  /**
   * @param message the payload (typically hash of message) that was signed when this signature was created.
   * @return the recovered public key.
   */
  @Override
  public BCECPublicKey recoverPublicKey(byte[] message) {

    BCECPublicKey publicKey = recoverPublicKey(message, getRecoveryIndex());
    if (publicKey != null) {
      return publicKey;
    }
    throw new IllegalArgumentException(
        "Can not recover public key from signature. Most probably you did not provide the same playload as when creating the signature.");
  }

  /**
   * @param curve the {@link #getCurve() elliptic curve}.
   * @param r the value {@link #getR() r}.
   * @param s the value {@link #getS() s}.
   * @param message the signed message (hash).
   * @param publicKey the {@link BCECPublicKey} that was used to sign the message.
   * @param recoveryOffset the {@link #getRecoveryOffset() recovery offset}.
   * @return the signature.
   */
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
