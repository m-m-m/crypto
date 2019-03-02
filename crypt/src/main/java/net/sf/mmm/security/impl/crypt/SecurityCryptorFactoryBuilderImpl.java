package net.sf.mmm.security.impl.crypt;

import net.sf.mmm.security.api.crypt.AbstractSecuritySetCryptorFactory;
import net.sf.mmm.security.api.crypt.SecurityCryptorConfig;
import net.sf.mmm.security.api.crypt.SecurityCryptorFactory;
import net.sf.mmm.security.api.crypt.SecurityCryptorFactoryBuilder;
import net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorConfig;
import net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorFactory;
import net.sf.mmm.security.api.crypt.symmetric.SecuritySymmetricCryptorConfig;
import net.sf.mmm.security.api.crypt.symmetric.SecuritySymmetricCryptorFactory;
import net.sf.mmm.security.api.provider.AbstractSecurityGetProvider;
import net.sf.mmm.security.api.random.AbstractSecurityGetRandomFactory;
import net.sf.mmm.security.impl.crypt.asymmetric.SecurityAsymmetricCryptorFactoryImpl;
import net.sf.mmm.security.impl.crypt.symmetric.SecuritySymmetricCryptorFactoryImpl;

/**
 * Implementation of {@link SecurityCryptorFactoryBuilder}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityCryptorFactoryBuilderImpl extends SecurityCryptorFactoryBuilder,
    AbstractSecuritySetCryptorFactory<SecurityCryptorFactory>, AbstractSecurityGetProvider, AbstractSecurityGetRandomFactory {

  @Override
  default SecurityCryptorFactory cryptUnsafe(SecurityCryptorConfig<?> configuration) {

    if (configuration instanceof SecuritySymmetricCryptorConfig) {
      return crypt((SecuritySymmetricCryptorConfig) configuration);
    } else if (configuration instanceof SecurityAsymmetricCryptorConfig) {
      return crypt((SecurityAsymmetricCryptorConfig) configuration);
    } else {
      throw new IllegalArgumentException(configuration.getClass().getName());
    }
  }

  @Override
  default SecurityAsymmetricCryptorFactory crypt(SecurityAsymmetricCryptorConfig configuration) {

    SecurityAsymmetricCryptorFactory factory = new SecurityAsymmetricCryptorFactoryImpl(configuration, getProvider(),
        getRandomFactoryRequired());
    setCryptorFactory(factory);
    return factory;
  }

  @Override
  default SecuritySymmetricCryptorFactory crypt(SecuritySymmetricCryptorConfig configuration) {

    SecuritySymmetricCryptorFactoryImpl factory = new SecuritySymmetricCryptorFactoryImpl(configuration, getProvider(),
        getRandomFactoryRequired());
    setCryptorFactory(factory);
    return factory;
  }

}
