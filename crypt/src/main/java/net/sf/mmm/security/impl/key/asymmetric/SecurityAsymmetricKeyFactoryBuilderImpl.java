package net.sf.mmm.security.impl.key.asymmetric;

import net.sf.mmm.security.api.key.asymmetric.AbstractSecuritySetAsymmetricKeyFactory;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyConfig;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyFactory;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyFactoryBuilder;
import net.sf.mmm.security.api.provider.AbstractSecurityGetProvider;
import net.sf.mmm.security.api.random.AbstractSecurityGetRandomFactory;

/**
 * Implementation of {@link SecurityAsymmetricKeyFactoryBuilder}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityAsymmetricKeyFactoryBuilderImpl extends SecurityAsymmetricKeyFactoryBuilder,
    AbstractSecurityGetProvider, AbstractSecurityGetRandomFactory, AbstractSecuritySetAsymmetricKeyFactory {

  @Override
  default SecurityAsymmetricKeyFactory key(SecurityAsymmetricKeyConfig configuration) {

    SecurityAsymmetricKeyFactoryImpl factory =
        new SecurityAsymmetricKeyFactoryImpl(configuration, getProvider(), getRandomFactoryRequired());
    setAsymmetricKeyFactory(factory);
    return factory;
  }

}
