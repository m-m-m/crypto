package net.sf.mmm.security.api.key.store.access;

import net.sf.mmm.security.api.SecurityAccess;
import net.sf.mmm.security.api.key.store.SecurityKeyStore;
import net.sf.mmm.security.api.key.store.SecurityKeyStoreConfig;
import net.sf.mmm.security.api.key.store.SecurityKeyStoreImpl;

/**
 * {@link SecurityAccess} to {@link #newKeyStore() create} instances of {@link SecurityKeyStore}.
 *
 * @since 1.0.0
 */
public abstract class SecurityAccessKeyStore extends SecurityAccess {

  private final SecurityKeyStoreConfig config;

  /**
   * The constructor.
   *
   * @param config the {@link SecurityKeyStoreConfig}.
   */
  public SecurityAccessKeyStore(SecurityKeyStoreConfig config) {

    super();
    this.config = config;
  }

  /**
   * @return the {@link SecurityKeyStoreConfig}.
   */
  public SecurityKeyStoreConfig getConfig() {

    return this.config;
  }

  /**
   * @return the new {@link SecurityKeyStore} instance.
   */
  public SecurityKeyStore newKeyStore() {

    return new SecurityKeyStoreImpl(this.config);
  }

}
