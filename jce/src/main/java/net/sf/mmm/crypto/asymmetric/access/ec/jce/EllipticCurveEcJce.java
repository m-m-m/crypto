package net.sf.mmm.crypto.asymmetric.access.ec.jce;

import java.math.BigInteger;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

import net.sf.mmm.crypto.algorithm.CryptoAlgorithmParameterConfig;

/**
 * Implementation of {@link CryptoAlgorithmParameterConfig} for Elliptic Curves using bouncy castle
 * ({@link ECParameterSpec}).
 *
 * @since 1.0.0
 */
public class EllipticCurveEcJce extends CryptoAlgorithmParameterConfig {

  private final String curveName;

  private ECParameterSpec ecParameters;

  /**
   * The constructor.
   *
   * @param curveName the {@link #getCurveName() curve name}.
   */
  public EllipticCurveEcJce(String curveName) {

    super();
    this.curveName = curveName;
  }

  /**
   * @return the {@link ECParameterSpec}.
   */
  @Override
  public ECParameterSpec getAlgorithmParameters() {

    if (this.ecParameters == null) {
      EllipticCurve curve = null;
      ECPoint g = null;
      BigInteger n = null;
      int h = 0;
      this.ecParameters = new ECParameterSpec(curve, g, n, h);
    }
    return this.ecParameters;
  }

  /**
   * @return the curve name.
   */
  public String getCurveName() {

    return this.curveName;
  }

}
