package net.sf.mmm.security.api.key.asymmetric;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmRsa;
import net.sf.mmm.security.api.key.asymmetric.spec.SecurityAsymmetricKeySpecFactoryPkcs8;
import net.sf.mmm.security.api.key.asymmetric.spec.SecurityAsymmetricKeySpecFactoryX509;

/**
 * {@link SecurityAsymmetricKeyConfig} for {@link SecurityAlgorithmRsa RSA}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityAsymmetricKeyConfigRsa extends SecurityAsymmetricKeyConfig
    implements SecurityAlgorithmRsa {

  /** {@link #ALGORITHM_RSA RSA} with a {@link #getKeyLength() key length} of 4096 bits. */
  public static final SecurityAsymmetricKeyConfigRsa RSA_4096 =
      new SecurityAsymmetricKeyConfigRsa(4096);

  /**
   * The constructor.
   *
   * @param keyLength the {@link #getKeyLength() key length} in bits.
   */
  public SecurityAsymmetricKeyConfigRsa(int keyLength) {
    super(ALGORITHM_RSA, keyLength, SecurityAsymmetricKeySpecFactoryPkcs8.INSTANCE,
        SecurityAsymmetricKeySpecFactoryX509.INSTANCE);
  }

}
