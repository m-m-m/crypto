package net.sf.mmm.security.impl.crypt.asymmetric;

import java.security.Provider;

import net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorConfig;
import net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorFactory;
import net.sf.mmm.security.api.random.SecurityRandomFactory;
import net.sf.mmm.security.impl.crypt.SecurityCryptorFactoryImpl;

/**
 * Implementation of {@link SecurityAsymmetricCryptorFactory}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityAsymmetricCryptorFactoryImpl extends SecurityCryptorFactoryImpl implements SecurityAsymmetricCryptorFactory {

  private final SecurityAsymmetricCryptorConfig config;

  /**
   * The constructor.
   *
   * @param config the {@link SecurityAsymmetricCryptorConfig}.
   * @param provider the security {@link Provider}.
   * @param randomFactory the {@link SecurityRandomFactory}.
   */
  public SecurityAsymmetricCryptorFactoryImpl(SecurityAsymmetricCryptorConfig config, Provider provider,
      SecurityRandomFactory randomFactory) {

    super(provider, randomFactory);
    this.config = config;
  }

  @Override
  public SecurityAsymmetricCryptorConfig getConfig() {

    return this.config;
  }

}
