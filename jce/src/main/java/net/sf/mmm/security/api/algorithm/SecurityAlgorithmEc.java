package net.sf.mmm.security.api.algorithm;

/**
 * The {@link SecurityAlgorithm} EC (Elliptic Curves). For details see
 * <a href="https://en.wikipedia.org/wiki/Elliptic_curve_cryptography">ECC</a>.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityAlgorithmEc extends SecurityAlgorithm {

  /** The {@link #getAlgorithm() algorithm} name {@value}. */
  String ALGORITHM_EC = "EC";

  @Override
  default String getAlgorithm() {

    return ALGORITHM_EC;
  }

}
