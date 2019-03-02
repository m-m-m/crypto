package net.sf.mmm.security.api.algorithm;

/**
 * The {@link SecurityAlgorithm}
 * <a href="https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm">ECDSA</a> (Elliptic Curve Digital
 * Signature Algorithm). For details see <a href="https://en.wikipedia.org/wiki/Elliptic_curve_cryptography">ECC</a>.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityAlgorithmEcDsa extends SecurityAlgorithm {

  /** The {@link #getAlgorithm() algorithm} name {@value}. */
  String ALGORITHM_ECDSA = "ECDSA";

  @Override
  default String getAlgorithm() {

    return ALGORITHM_ECDSA;
  }

}
