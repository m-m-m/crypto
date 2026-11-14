package io.github.mmm.crypto.key.store.access;

import io.github.mmm.crypto.CryptoAccess;
import io.github.mmm.crypto.key.store.KeyStoreConfig;
import io.github.mmm.crypto.key.store.KeyStoreFacade;
import io.github.mmm.crypto.key.store.KeyStoreFacadeImpl;

/// [CryptoAccess] to [create][#newKeyStore()] instances of [KeyStoreFacade].
///
/// @since 1.0.0
public abstract class KeyStoreAccess extends CryptoAccess {

  private final KeyStoreConfig config;

  /// The constructor.
  ///
  /// @param config the [KeyStoreConfig].
  public KeyStoreAccess(KeyStoreConfig config) {

    super();
    this.config = config;
  }

  /// @return the [KeyStoreConfig].
  public KeyStoreConfig getConfig() {

    return this.config;
  }

  /// @return the new [KeyStoreFacade] instance.
  public KeyStoreFacade newKeyStore() {

    return new KeyStoreFacadeImpl(this.config);
  }

}
