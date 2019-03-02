package net.sf.mmm.security.api.crypt.asymmetric;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmParameterConfig;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.spec.ECParameterSpec;

/**
 * Implementation of {@link SecurityAlgorithmParameterConfig} for Elliptic Curves using bouncy castle
 * ({@link ECParameterSpec}).
 *
 * @since 1.0.0
 */
public class SecurityAlgorithmParameterConfigEcBc extends SecurityAlgorithmParameterConfig {

  private final String curveName;

  private ECParameterSpec ecParameters;

  /**
   * The constructor.
   *
   * @param curveName the {@link #getCurveName() curve name}.
   */
  public SecurityAlgorithmParameterConfigEcBc(String curveName) {

    super();
    this.curveName = curveName;
  }

  /**
   * @return the {@link ECParameterSpec}.
   */
  @Override
  public ECParameterSpec getAlgorithmParameters() {

    if (this.ecParameters == null) {
      X9ECParameters ecP = CustomNamedCurves.getByName(getCurveName());
      this.ecParameters = new ECParameterSpec(ecP.getCurve(), ecP.getG(), ecP.getN(), ecP.getH(), ecP.getSeed());
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
