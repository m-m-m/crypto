package net.sf.mmm.security.api.asymmetric.access.ec.jce;

import java.math.BigInteger;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmParameterConfig;

/**
 * Implementation of {@link SecurityAlgorithmParameterConfig} for Elliptic Curves using bouncy castle
 * ({@link ECParameterSpec}).
 *
 * @since 1.0.0
 */
public class SecurityElliptocCurveEcJce extends SecurityAlgorithmParameterConfig {

  private final String curveName;

  private ECParameterSpec ecParameters;

  /**
   * The constructor.
   *
   * @param curveName the {@link #getCurveName() curve name}.
   */
  public SecurityElliptocCurveEcJce(String curveName) {

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
