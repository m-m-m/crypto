package net.sf.mmm.security.api.key.asymmetric;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmEc;
import net.sf.mmm.security.api.key.asymmetric.spec.SecurityAsymmetricKeySpecFactoryPkcs8;
import net.sf.mmm.security.api.key.asymmetric.spec.SecurityAsymmetricKeySpecFactoryX509;

/**
 * {@link SecurityAsymmetricKeyConfig} for {@link SecurityAlgorithmEc EC}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityAsymmetricKeyConfigEc extends SecurityAsymmetricKeyConfig
    implements SecurityAlgorithmEc {

  /** {@link #ALGORITHM_EC EC} with a {@link #getKeyLength() key length} of 256 bits. */
  public static final SecurityAsymmetricKeyConfigEc EC_256 = new SecurityAsymmetricKeyConfigEc(256);

  /**
   * The constructor.
   *
   * @param keyLength the {@link #getKeyLength() key length} in bits.
   */
  public SecurityAsymmetricKeyConfigEc(int keyLength) {
    super(ALGORITHM_EC, keyLength, SecurityAsymmetricKeySpecFactoryPkcs8.INSTANCE,
        SecurityAsymmetricKeySpecFactoryX509.INSTANCE);
  }

}
