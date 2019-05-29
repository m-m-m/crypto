package net.sf.mmm.crypto.asymmetric.access.ec.bc;

import java.math.BigInteger;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.spec.ECParameterSpec;

/**
 * Configuration for a specific <a href="https://en.wikipedia.org/wiki/Elliptic_curve_cryptography">elliptic curve</a>
 * based on bouncy castles {@link ECParameterSpec}.
 *
 * @since 1.0.0
 */
public abstract class CryptoEllipticCurveBc {

  private final String curveName;

  private ECParameterSpec ecParameters;

  private BigInteger q;

  private BigInteger halfN;

  /**
   * The constructor.
   *
   * @param curveName the {@link #getCurveName() curve name}.
   */
  CryptoEllipticCurveBc(String curveName) {

    super();
    this.curveName = curveName;
  }

  /**
   * @return the curve name.
   */
  public String getCurveName() {

    return this.curveName;
  }

  /**
   * @return the {@link ECParameterSpec}.
   */
  public ECParameterSpec getEcParameters() {

    if (this.ecParameters == null) {
      synchronized (CryptoEllipticCurveBc.class) {
        if (this.ecParameters == null) {
          X9ECParameters ecP = CustomNamedCurves.getByName(this.curveName);
          this.ecParameters = new ECParameterSpec(ecP.getCurve(), ecP.getG(), ecP.getN(), ecP.getH(), ecP.getSeed());
        }
      }
    }
    return this.ecParameters;
  }

  /**
   * @return the Q value of the {@link ECParameterSpec#getCurve() curve}.
   */
  public BigInteger getQ() {

    if (this.q == null) {
      synchronized (CryptoEllipticCurveBc.class) {
        if (this.q == null) {
          this.q = determineCurveQ();
        }
      }
    }
    return this.q;
  }

  /**
   * @return the {@link #getQ() Q value}.
   */
  protected abstract BigInteger determineCurveQ();

  /**
   * @return halfN
   */
  public BigInteger getHalfN() {

    if (this.halfN == null) {
      synchronized (CryptoEllipticCurveBc.class) {
        if (this.halfN == null) {
          this.halfN = getEcParameters().getN().shiftRight(1);
        }
      }
    }
    return this.halfN;
  }

  /**
   * @return the length of the curve order and keys in bits.
   */
  public int getBitLength() {

    return getEcParameters().getCurve().getOrder().bitLength();
  }

  /**
   * @return the length of the curve order and keys in bytes.
   */
  public int getByteLength() {

    return getByteLength(getEcParameters());
  }

  /**
   * @param ecParameters the {@link ECParameterSpec}.
   * @return the length of the curve order in bytes. This is also the length of the (compressed) keys except for a
   *         potential extra byte.
   */
  public static int getByteLength(ECParameterSpec ecParameters) {

    return (ecParameters.getCurve().getOrder().bitLength() + 7) / 8;
  }

}
