package net.sf.mmm.security.api.crypt.asymmetric;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmRsa;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyConfigRsa;

/**
 * {@link SecurityAsymmetricCryptorConfig} for {@link SecurityAlgorithmRsa RSA}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public final class SecurityAsymmetricCryptorConfigRsa
    extends SecurityAsymmetricCryptorConfigBidirectional implements SecurityAlgorithmRsa {

  /**
   * {@link SecurityAlgorithmRsa RSA} with a {@link SecurityAsymmetricKeyConfigRsa#getKeyLength() key length} of 4096
   * bits.
   */
  public static final SecurityAsymmetricCryptorConfigRsa RSA_4096 = new SecurityAsymmetricCryptorConfigRsa(
      SecurityAsymmetricKeyConfigRsa.RSA_4096);

  /**
   * The constructor.
   *
   * @param keyAlgorithmConfig the {@link SecurityAsymmetricKeyConfigRsa RSA key config}.
   */
  public SecurityAsymmetricCryptorConfigRsa(SecurityAsymmetricKeyConfigRsa keyAlgorithmConfig) {

    super(ALGORITHM_RSA, keyAlgorithmConfig, 0);
  }

}
