package net.sf.mmm.crypto.asymmetric.sign.ec.bc;

import java.math.BigInteger;

import net.sf.mmm.crypto.asymmetric.access.ec.bc.CryptoEllipticCurveBc;
import net.sf.mmm.crypto.asymmetric.key.ec.bc.AsymmetricKeyPairEcBc;
import net.sf.mmm.crypto.asymmetric.sign.SignatureBinary;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

/**
 * {@link SignatureBinary} for ECDSA based on {@link net.sf.mmm.crypto.provider.BouncyCastle}.
 *
 * @since 1.0.0
 */
public abstract class SignatureEcBc extends SignatureBinary {

  private final CryptoEllipticCurveBc curve;

  private BigInteger r;

  private BigInteger s;

  /**
   * The constructor.
   *
   * @param curve the {@link #getCurve() elliptic curve}.
   * @param data the {@link #getData() binary data}.
   * @param r - see {@link #getR()}.
   * @param s - see {@link #getS()}.
   */
  public SignatureEcBc(CryptoEllipticCurveBc curve, byte[] data, BigInteger r, BigInteger s) {

    super(data);
    this.curve = curve;
    this.r = r;
    this.s = s;
  }

  /**
   * The constructor.
   *
   * @param curve the {@link #getCurve() elliptic curve}.
   * @param data the {@link #getData() binary data}.
   */
  public SignatureEcBc(CryptoEllipticCurveBc curve, byte[] data) {

    super(data);
    this.curve = curve;
  }

  private void initRS() {

    if (this.r == null) {
      assert (this.s == null);
      deserialize();
    } else {
      assert (this.s != null);
    }
  }

  /**
   * @return number of bytes reserved at the beginning (header) of the {@link #getData() binary} data.
   */
  protected int getHead() {

    return 0;
  }

  /**
   * Initializes the internal fields like {@link #getR() r} and {@link #getS() s} from {@link #getData() binary data}.
   */
  protected void deserialize() {

    int len = this.data.length;
    int head = getHead();
    int rsLen = len - head;
    if (rsLen % 2 != 0) {
      throw new IllegalStateException("Invalid signature length: " + len);
    }
    int biLen = rsLen / 2;
    byte[] biData = new byte[biLen];
    System.arraycopy(this.data, head, biData, 0, biLen);
    this.r = new BigInteger(1, biData);
    System.arraycopy(this.data, head + biLen, biData, 0, biLen);
    this.s = new BigInteger(1, biData);
  }

  /**
   * @param head the number of bytes reserved at the beginning.
   * @param r the value {@link #getR() r}.
   * @param s the value {@link #getS() s}.
   * @return the {@link #getData() binary data}.
   */
  protected static byte[] createData(int head, BigInteger r, BigInteger s) {

    byte[] rData = r.toByteArray();
    byte[] sData = s.toByteArray();
    int rStart = 0;
    int rLen = rData.length;
    if (rData[0] == 0) {
      rStart = 1;
      rLen--;
    }
    int sStart = 0;
    int sLen = sData.length;
    if (sData[0] == 0) {
      sStart = 1;
      sLen--;
    }
    int maxLen = rLen;
    if (maxLen < sLen) {
      maxLen = sLen;
    }
    byte[] data = new byte[head + maxLen + maxLen];
    System.arraycopy(rData, rStart, data, head, rLen);
    System.arraycopy(sData, sStart, data, head + maxLen, sLen);
    return data;
  }

  /**
   * @return r
   */
  public BigInteger getR() {

    initRS();
    return this.r;
  }

  /**
   * @return s
   */
  public BigInteger getS() {

    initRS();
    return this.s;
  }

  /**
   * @return the {@link CryptoEllipticCurveBc elliptic curve}.
   */
  protected CryptoEllipticCurveBc getCurve() {

    return this.curve;
  }

  /**
   * @param message the payload (typically hash of message) that was signed when this signature was created.
   * @param recoveryIndex the recovery index for public key recovery.
   * @return the recovered public key.
   */
  protected BCECPublicKey recoverPublicKey(byte[] message, byte recoveryIndex) {

    initRS();
    return recoverPublicKey(message, this.curve, this.r, this.s, recoveryIndex);
  }

  /**
   * @param message the payload (typically hash of message) that was signed when this signature was created.
   * @param curve the {@link CryptoEllipticCurveBc elliptic curve}.
   * @param r value {@link #getR() R}.
   * @param s value {@link #getS() S}.
   * @param publicKey the {@link BCECPublicKey public key} corresponding to the private key that was used to sign the
   *        {@code message}.
   * @return the {@link SignatureEcBcWithRecoveryId#getRecoveryIndex() recovery index}.
   */
  protected static byte calculateRecoveryIndex(byte[] message, CryptoEllipticCurveBc curve, BigInteger r, BigInteger s,
      BCECPublicKey publicKey) {

    byte recoveryIndex = -1;
    for (byte i = 0; i < 4; i++) {
      BCECPublicKey key = recoverPublicKey(message, curve, r, s, i);
      if (key != null) {
        if (key.getQ().equals(publicKey.getQ())) {
          recoveryIndex = i;
          break;
        }
      }
    }
    if (recoveryIndex == -1) {
      throw new IllegalArgumentException("Failed to recover public key from signature.");
    }
    return recoveryIndex;
  }

  /**
   * @param message the payload (typically hash of message) that was signed when this signature was created.
   * @param curve the {@link CryptoEllipticCurveBc elliptic curve}.
   * @param r value {@link #getR() R}.
   * @param s value {@link #getS() S}.
   * @param recoveryIndex the {@link SignatureEcBcWithRecoveryId#getRecoveryIndex() recovery index} for public key
   *        recovery.
   * @return the recovered public key.
   */
  protected static BCECPublicKey recoverPublicKey(byte[] message, CryptoEllipticCurveBc curve, BigInteger r, BigInteger s,
      byte recoveryIndex) {

    BigInteger e = new BigInteger(1, message);

    ECParameterSpec ecParameters = curve.getEcParameters();
    BigInteger n = ecParameters.getN();
    BigInteger x = r;
    if (recoveryIndex > 2) {
      x = r.add(n);
    }
    BigInteger qCurve = curve.getQ();
    if (x.compareTo(qCurve) >= 0) {
      return null;
    }

    ECCurve ecCurve = ecParameters.getCurve();
    ECFieldElement xCurve = ecCurve.fromBigInteger(x);
    ECFieldElement alpha = xCurve.multiply(xCurve.square().add(ecCurve.getA())).add(ecCurve.getB());
    ECFieldElement beta = alpha.sqrt();
    if (beta == null) {
      throw new IllegalStateException();
    }
    ECPoint ecPoint;
    BigInteger nBeta = beta.toBigInteger();
    if (nBeta.testBit(0) == ((recoveryIndex & 1) == 1)) {
      ecPoint = ecCurve.createPoint(xCurve.toBigInteger(), nBeta);
    } else {
      ECFieldElement y = ecCurve.fromBigInteger(qCurve.subtract(nBeta));
      ecPoint = ecCurve.createPoint(xCurve.toBigInteger(), y.toBigInteger());
    }

    if (!ecPoint.multiply(n).isInfinity()) {
      return null;
    }
    BigInteger eInverse = BigInteger.ZERO.subtract(e).mod(n);
    BigInteger rInverse = r.modInverse(n);
    BigInteger srInverse = rInverse.multiply(s).mod(n);
    BigInteger erInverse = rInverse.multiply(eInverse).mod(n);
    ECPoint qKey = ECAlgorithms.sumOfTwoMultiplies(ecParameters.getG(), erInverse, ecPoint, srInverse);

    return AsymmetricKeyPairEcBc.createPublicKey(qKey, ecParameters);
  }

}
