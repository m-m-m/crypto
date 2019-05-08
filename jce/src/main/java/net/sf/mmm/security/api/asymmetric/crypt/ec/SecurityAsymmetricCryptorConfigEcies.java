package net.sf.mmm.security.api.asymmetric.crypt.ec;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmEcIes;
import net.sf.mmm.security.api.asymmetric.crypt.SecurityAsymmetricCryptorConfig;
import net.sf.mmm.security.api.provider.SecurityProvider;

/**
 * {@link SecurityAsymmetricCryptorConfig} for {@link SecurityAlgorithmEcIes ECIES}.
 *
 * @param <PR> type of {@link ECPrivateKey}.
 * @param <PU> type of {@link ECPublicKey}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public final class SecurityAsymmetricCryptorConfigEcies<PR extends ECPrivateKey, PU extends ECPublicKey>
    extends SecurityAsymmetricCryptorConfig<PR, PU> implements SecurityAlgorithmEcIes {

  /**
   * The constructor.
   *
   * @param provider the {@link SecurityProvider}.
   */
  public SecurityAsymmetricCryptorConfigEcies(SecurityProvider provider) {

    super(ALGORITHM_ECIES, 0, provider);
  }

}
