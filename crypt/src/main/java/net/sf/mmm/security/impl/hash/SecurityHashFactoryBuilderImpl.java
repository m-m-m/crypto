package net.sf.mmm.security.impl.hash;

import net.sf.mmm.security.api.hash.AbstractSecuritySetHashFactory;
import net.sf.mmm.security.api.hash.SecurityHashConfig;
import net.sf.mmm.security.api.hash.SecurityHashFactory;
import net.sf.mmm.security.api.hash.SecurityHashFactoryBuilder;
import net.sf.mmm.security.api.provider.AbstractSecurityGetProvider;
import net.sf.mmm.security.api.random.AbstractSecurityGetRandomFactory;

/**
 * Implementation of {@link SecurityHashFactoryBuilder}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityHashFactoryBuilderImpl extends SecurityHashFactoryBuilder, AbstractSecurityGetProvider,
    AbstractSecurityGetRandomFactory, AbstractSecuritySetHashFactory {

  @Override
  default SecurityHashFactory hash(SecurityHashConfig configuration) {

    SecurityHashFactoryImpl factory = new SecurityHashFactoryImpl(configuration, getProvider());
    setHashFactory(factory);
    return factory;
  }

}
