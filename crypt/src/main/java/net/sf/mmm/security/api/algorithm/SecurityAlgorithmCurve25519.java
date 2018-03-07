package net.sf.mmm.security.api.algorithm;

/**
 * The {@link SecurityAlgorithm} curve 25519 (actually key parameters for EC). For details see
 * <a href="https://en.wikipedia.org/wiki/Elliptic_curve_cryptography">ECC</a>.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityAlgorithmCurve25519 extends SecurityAlgorithm {

  /** The {@link #getAlgorithm() algorithm} name {@value}. */
  String ALGORITHM_CURVE_25519 = "curve25519";

  @Override
  default String getAlgorithm() {

    return ALGORITHM_CURVE_25519;
  }

}
