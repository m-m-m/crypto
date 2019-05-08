package net.sf.mmm.security.api.algorithm;

/**
 * The {@link SecurityAlgorithm} <a href="https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman">ECDH</a>
 * (Elliptic Curves Diffie-Hellman). For details see
 * <a href="https://en.wikipedia.org/wiki/Elliptic_curve_cryptography">ECC</a>.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityAlgorithmEcDh extends SecurityAlgorithm {

  /** The {@link #getAlgorithm() algorithm} name {@value}. */
  String ALGORITHM_ECDH = "ECDH";

  @Override
  default String getAlgorithm() {

    return ALGORITHM_ECDH;
  }

}
