package net.sf.mmm.security.impl.random;

import net.sf.mmm.security.api.SecurityFactoryBuilder;
import net.sf.mmm.security.api.hash.SecurityHashFactoryBuilder;
import net.sf.mmm.security.api.provider.AbstractSecurityGetProvider;
import net.sf.mmm.security.api.random.AbstractSecurityRandomFactoryBuilder;
import net.sf.mmm.security.api.random.AbstractSecuritySetRandomFactory;
import net.sf.mmm.security.api.random.SecurityRandomConfig;
import net.sf.mmm.security.api.random.SecurityRandomFactory;

/**
 * Implementation of {@link SecurityHashFactoryBuilder}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityRandomFactoryBuilderImpl
    extends AbstractSecurityRandomFactoryBuilder<SecurityFactoryBuilder>, AbstractSecurityGetProvider, AbstractSecuritySetRandomFactory {

  @Override
  default SecurityRandomFactory random(SecurityRandomConfig configuration) {

    SecurityRandomFactoryImpl factory = new SecurityRandomFactoryImpl(configuration, getProvider());
    setRandomFactory(factory);
    return factory;
  }

  @Override
  default SecurityRandomFactory random() {

    SecurityRandomFactoryImpl factory = SecurityRandomFactoryImpl.ofStrong();
    setRandomFactory(factory);
    return factory;
  }

  @Override
  default SecurityRandomFactory getRandomFactoryRequired() {

    SecurityRandomFactory factory = getRandomFactory();
    if (factory == null) {
      factory = random();
    }
    return factory;
  }

}
