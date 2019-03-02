package net.sf.mmm.security.api.key.asymmetric.ec.bc;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmCurve25519;
import net.sf.mmm.security.api.algorithm.SecurityAlgorithmSecp256k1;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.spec.ECParameterSpec;

/**
 * Configuration for a specific {@link net.sf.mmm.security.api.algorithm.SecurityAlgorithmEc Elliptic Curve} based on
 * bouncy castles {@link ECParameterSpec}.
 *
 * @since 1.0.0
 */
public class SecurityAsymmetricConfigEcBc {

  private final String curveName;

  private ECParameterSpec ecParameters;

  /** @see SecurityAlgorithmSecp256k1 */
  public static final SecurityAsymmetricConfigEcBc SECP256K1 = new SecurityAsymmetricConfigEcBc(
      SecurityAlgorithmSecp256k1.ALGORITHM_SECP_256K1);

  /** @see SecurityAlgorithmCurve25519 */
  public static final SecurityAsymmetricConfigEcBc CURVE25519 = new SecurityAsymmetricConfigEcBc(
      SecurityAlgorithmCurve25519.ALGORITHM_CURVE_25519);

  /**
   * The constructor.
   *
   * @param curveName the {@link #getCurveName() curve name}.
   */
  public SecurityAsymmetricConfigEcBc(String curveName) {

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
      X9ECParameters ecP = CustomNamedCurves.getByName(this.curveName);
      this.ecParameters = new ECParameterSpec(ecP.getCurve(), ecP.getG(), ecP.getN(), ecP.getH(), ecP.getSeed());
    }
    return this.ecParameters;
  }

}
