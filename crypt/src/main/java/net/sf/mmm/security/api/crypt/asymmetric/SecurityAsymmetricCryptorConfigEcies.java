package net.sf.mmm.security.api.crypt.asymmetric;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmEcies;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyConfigEc;

/**
 * {@link SecurityAsymmetricCryptorConfig} for {@link SecurityAlgorithmEcies ECIES}. This cipher is not included in
 * JAC/JCE so you need to use {@link org.bouncycastle.jce.provider.BouncyCastleProvider} as
 * {@link net.sf.mmm.security.api.provider.SecurityProviderBuilder#provider(java.security.Provider) configured
 * provider}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public final class SecurityAsymmetricCryptorConfigEcies extends SecurityAsymmetricCryptorConfigPublicPrivate implements SecurityAlgorithmEcies {

  /**
   * {@link SecurityAlgorithmEcies ECIES} with a {@link SecurityAsymmetricKeyConfigEc#getKeyLength() key length} of 256
   * bits.
   */
  public static final SecurityAsymmetricCryptorConfigEcies ECIES_256 = new SecurityAsymmetricCryptorConfigEcies(SecurityAsymmetricKeyConfigEc.EC_256);

  /**
   * The constructor.
   *
   * @param keyAlgorithmConfig the {@link SecurityAsymmetricKeyConfigEc EC key configuration}.
   */
  public SecurityAsymmetricCryptorConfigEcies(SecurityAsymmetricKeyConfigEc keyAlgorithmConfig) {

    super(ALGORITHM_ECIES, keyAlgorithmConfig, 0);
  }

}
