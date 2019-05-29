package net.sf.mmm.crypto.key.store.access;

import net.sf.mmm.crypto.CryptoAccess;
import net.sf.mmm.crypto.key.store.KeyStoreApi;
import net.sf.mmm.crypto.key.store.KeyStoreConfig;
import net.sf.mmm.crypto.key.store.KeyStoreImpl;

/**
 * {@link CryptoAccess} to {@link #newKeyStore() create} instances of {@link KeyStoreApi}.
 *
 * @since 1.0.0
 */
public abstract class KeyStoreAccess extends CryptoAccess {

  private final KeyStoreConfig config;

  /**
   * The constructor.
   *
   * @param config the {@link KeyStoreConfig}.
   */
  public KeyStoreAccess(KeyStoreConfig config) {

    super();
    this.config = config;
  }

  /**
   * @return the {@link KeyStoreConfig}.
   */
  public KeyStoreConfig getConfig() {

    return this.config;
  }

  /**
   * @return the new {@link KeyStoreApi} instance.
   */
  public KeyStoreApi newKeyStore() {

    return new KeyStoreImpl(this.config);
  }

}
