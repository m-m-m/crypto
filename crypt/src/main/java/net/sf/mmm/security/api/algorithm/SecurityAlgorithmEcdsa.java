package net.sf.mmm.security.api.algorithm;

/**
 * The {@link SecurityAlgorithm} ECDSA (Elliptic Curve TODO). For details see
 * <a href="https://en.wikipedia.org/wiki/Elliptic_curve_cryptography">ECC</a>.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityAlgorithmEcdsa extends SecurityAlgorithm {

  /** The {@link #getAlgorithm() algorithm} name {@value}. */
  String ALGORITHM_ECDSA = "ECDSA";

  @Override
  default String getAlgorithm() {

    return ALGORITHM_ECDSA;
  }

}
