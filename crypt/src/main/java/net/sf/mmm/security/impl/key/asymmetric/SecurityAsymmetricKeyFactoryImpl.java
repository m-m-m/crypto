package net.sf.mmm.security.impl.key.asymmetric;

import java.security.Provider;

import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyConfig;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyCreator;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyFactory;
import net.sf.mmm.security.api.random.SecurityRandomFactory;
import net.sf.mmm.security.impl.AbstractSecurityAlgorithmWithRandom;

/**
 * Implementation of {@link SecurityAsymmetricKeyFactory}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityAsymmetricKeyFactoryImpl extends AbstractSecurityAlgorithmWithRandom
    implements SecurityAsymmetricKeyFactory {

  private final SecurityAsymmetricKeyConfig config;

  /**
   * The constructor.
   *
   * @param config the {@link SecurityAsymmetricKeyConfig}.
   * @param provider the security {@link Provider}.
   * @param randomFactory the {@link SecurityRandomFactory}.
   */
  public SecurityAsymmetricKeyFactoryImpl(SecurityAsymmetricKeyConfig config, Provider provider,
      SecurityRandomFactory randomFactory) {
    super(provider, randomFactory);
    this.config = config;
  }

  @Override
  public String getAlgorithm() {

    return this.config.getAlgorithm();
  }

  @Override
  public SecurityAsymmetricKeyCreator newKeyCreator() {

    return new SecurityAsymmetricKeyCreatorImpl(this.config, getProvider(), getRandomFactory());
  }

}
