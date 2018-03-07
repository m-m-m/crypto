package net.sf.mmm.security.impl.key.store;

import net.sf.mmm.security.api.key.store.SecurityKeyStore;
import net.sf.mmm.security.api.key.store.SecurityKeyStoreConfig;
import net.sf.mmm.security.api.key.store.SecurityKeyStoreFactoryBuilder;
import net.sf.mmm.security.api.provider.AbstractSecurityGetProvider;

/**
 * Implementation of {@link SecurityKeyStoreFactoryBuilder}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityKeyStoreFactoryBuilderImpl extends SecurityKeyStoreFactoryBuilder, AbstractSecurityGetProvider {

  @Override
  default SecurityKeyStore keyStore(SecurityKeyStoreConfig configuration) {

    return new SecurityKeyStoreImpl(configuration, getProvider());
  }

}
