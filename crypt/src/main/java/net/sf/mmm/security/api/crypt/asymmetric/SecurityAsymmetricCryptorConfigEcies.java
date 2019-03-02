package net.sf.mmm.security.api.crypt.asymmetric;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmEcIes;
import net.sf.mmm.security.api.key.asymmetric.ec.jce.SecurityAsymmetricKeyConfigEcJce;

/**
 * {@link SecurityAsymmetricCryptorConfig} for {@link SecurityAlgorithmEcIes ECIES}. This cipher is not included in
 * JAC/JCE so you need to use {@link org.bouncycastle.jce.provider.BouncyCastleProvider} as
 * {@link net.sf.mmm.security.api.provider.SecurityProviderBuilder#provider(java.security.Provider) configured
 * provider}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public final class SecurityAsymmetricCryptorConfigEcies extends SecurityAsymmetricCryptorConfig implements SecurityAlgorithmEcIes {

  /**
   * {@link SecurityAlgorithmEcIes ECIES} with a {@link SecurityAsymmetricKeyConfigEcJce#getKeyLength() key length} of 256
   * bits.
   */
  public static final SecurityAsymmetricCryptorConfigEcies ECIES_256 = new SecurityAsymmetricCryptorConfigEcies(
      SecurityAsymmetricKeyConfigEcJce.EC_256);

  /**
   * The constructor.
   *
   * @param keyAlgorithmConfig the {@link SecurityAsymmetricKeyConfigEcJce EC key configuration}.
   */
  public SecurityAsymmetricCryptorConfigEcies(SecurityAsymmetricKeyConfigEcJce keyAlgorithmConfig) {

    super(ALGORITHM_ECIES, keyAlgorithmConfig, 0);
  }

}
