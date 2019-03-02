package net.sf.mmm.security.api.key.asymmetric.ec.bc;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmEcDh;
import net.sf.mmm.security.api.algorithm.SecurityAlgorithmSecp256k1;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyConfig;

/**
 * {@link SecurityAsymmetricKeyConfig} for {@link SecurityAlgorithmSecp256k1 Secp256k1}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityAsymmetricKeyConfigSecp256k1 extends SecurityAsymmetricKeyConfigEcBc implements SecurityAlgorithmEcDh {

  /** {@link #ALGORITHM_ECDH ECDH} for {@link SecurityAlgorithmSecp256k1 Secp256k1}. */
  public static final SecurityAsymmetricKeyConfigSecp256k1 SECP_256K1 = new SecurityAsymmetricKeyConfigSecp256k1();

  /**
   * The constructor.
   */
  public SecurityAsymmetricKeyConfigSecp256k1() {

    super(ALGORITHM_ECDH, SecurityAsymmetricConfigEcBc.SECP256K1, 256);
  }

}
