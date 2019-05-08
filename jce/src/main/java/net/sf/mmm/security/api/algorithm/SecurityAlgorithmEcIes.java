package net.sf.mmm.security.api.algorithm;

/**
 * The {@link SecurityAlgorithm} ECIES (Elliptic Curve Integrated Encryption Scheme). For details see
 * <a href="https://en.wikipedia.org/wiki/Elliptic_curve_cryptography">ECC</a>.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityAlgorithmEcIes extends SecurityAlgorithm {

  /** The {@link #getAlgorithm() algorithm} name {@value}. */
  String ALGORITHM_ECIES = "ECIES";

  @Override
  default String getAlgorithm() {

    return ALGORITHM_ECIES;
  }

}
