package net.sf.mmm.security.api.algorithm;

/**
 * The {@link SecurityAlgorithm} <a href="https://en.bitcoin.it/wiki/Secp256k1">Secp256k1</a> (actually key parameters
 * for EC). For details see <a href="https://en.wikipedia.org/wiki/Elliptic_curve_cryptography">ECC</a>.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityAlgorithmSecp256k1 extends SecurityAlgorithm {

  /** The {@link #getAlgorithm() algorithm} name {@value}. */
  String ALGORITHM_SECP_256K1 = "secp256k1";

  @Override
  default String getAlgorithm() {

    return ALGORITHM_SECP_256K1;
  }

}
