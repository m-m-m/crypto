package net.sf.mmm.security.impl.key.symmetric;

import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyFactoryBuilder;
import net.sf.mmm.security.api.key.symmetric.AbstractSecuritySetSymmetricKeyFactory;
import net.sf.mmm.security.api.key.symmetric.SecuritySymmetricKeyConfig;
import net.sf.mmm.security.api.key.symmetric.SecuritySymmetricKeyFactory;
import net.sf.mmm.security.api.key.symmetric.SecuritySymmetricKeyFactoryBuilder;
import net.sf.mmm.security.api.provider.AbstractSecurityGetProvider;

/**
 * Implementation of {@link SecurityAsymmetricKeyFactoryBuilder}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecuritySymmetricKeyFactoryBuilderImpl
    extends SecuritySymmetricKeyFactoryBuilder, AbstractSecurityGetProvider, AbstractSecuritySetSymmetricKeyFactory {

  @Override
  default SecuritySymmetricKeyFactory key(SecuritySymmetricKeyConfig configuration) {

    SecuritySymmetricKeyFactoryImpl factory = new SecuritySymmetricKeyFactoryImpl(configuration, getProvider());
    setSymmetricKeyFactory(factory);
    return factory;
  }

}
