package net.sf.mmm.security.api.key.store;

import java.security.KeyStore;

/**
 * Interface for a factory to {@link #keyStore(SecurityKeyStoreConfig) create} instances of {@link SecurityKeyStore}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityKeyStoreFactoryBuilder {

  /**
   * @param configuration the {@link SecurityKeyStoreConfig}.
   * @return the loaded {@link KeyStore}.
   */
  SecurityKeyStore keyStore(SecurityKeyStoreConfig configuration);

}
