package net.sf.mmm.security.api.key.asymmetric.ec.bc;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmCurve25519;
import net.sf.mmm.security.api.algorithm.SecurityAlgorithmEcDsa;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyConfig;

/**
 * {@link SecurityAsymmetricKeyConfig} for {@link SecurityAlgorithmCurve25519 curve 25519}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityAsymmetricKeyConfigCurve25519 extends SecurityAsymmetricKeyConfigEcBc implements SecurityAlgorithmEcDsa {

  /** {@link #ALGORITHM_ECDSA ECDSA} for {@link SecurityAlgorithmCurve25519 curve 25519}. */
  public static final SecurityAsymmetricKeyConfigCurve25519 CURVE_25519 = new SecurityAsymmetricKeyConfigCurve25519();

  /**
   * The constructor.
   */
  public SecurityAsymmetricKeyConfigCurve25519() {

    super(ALGORITHM_ECDSA, SecurityAsymmetricConfigEcBc.CURVE25519, 256);
  }

}
