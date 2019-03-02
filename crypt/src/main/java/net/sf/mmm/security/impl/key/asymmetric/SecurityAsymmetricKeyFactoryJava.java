package net.sf.mmm.security.impl.key.asymmetric;

import java.security.Provider;

import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyConfig;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyCreator;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyFactory;
import net.sf.mmm.security.api.random.SecurityRandomFactory;

/**
 * Implementation of {@link SecurityAsymmetricKeyFactory}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityAsymmetricKeyFactoryJava extends AbstractSecurityAsymmetricKeyFactory {

  /**
   * The constructor.
   *
   * @param config the {@link SecurityAsymmetricKeyConfig}.
   * @param provider the security {@link Provider}.
   * @param randomFactory the {@link SecurityRandomFactory}.
   */
  public SecurityAsymmetricKeyFactoryJava(SecurityAsymmetricKeyConfig config, Provider provider, SecurityRandomFactory randomFactory) {

    super(config, provider, randomFactory);
  }

  @Override
  public SecurityAsymmetricKeyCreator newKeyCreator() {

    return new SecurityAsymmetricKeyCreatorImpl(getConfig(), getProvider(), getRandomFactory());
  }

}
