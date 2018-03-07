package net.sf.mmm.security.impl.crypt.symmetric;

import java.security.Provider;

import net.sf.mmm.security.api.crypt.symmetric.SecuritySymmetricCryptorConfig;
import net.sf.mmm.security.api.crypt.symmetric.SecuritySymmetricCryptorFactory;
import net.sf.mmm.security.api.random.SecurityRandomFactory;
import net.sf.mmm.security.impl.crypt.SecurityCryptorFactoryImpl;

/**
 * Implementation of {@link SecuritySymmetricCryptorFactory}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecuritySymmetricCryptorFactoryImpl extends SecurityCryptorFactoryImpl
    implements SecuritySymmetricCryptorFactory {

  /**
   * The constructor.
   *
   * @param config the {@link SecuritySymmetricCryptorConfig}.
   * @param provider the security {@link Provider}.
   * @param randomFactory the {@link SecurityRandomFactory}.
   */
  public SecuritySymmetricCryptorFactoryImpl(SecuritySymmetricCryptorConfig config, Provider provider,
      SecurityRandomFactory randomFactory) {

    super(config, provider, randomFactory);
  }

}
