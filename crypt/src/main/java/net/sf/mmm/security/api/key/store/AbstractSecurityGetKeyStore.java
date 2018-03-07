package net.sf.mmm.security.api.key.store;

/**
 * Abstract interface to {@link #getKeyStore() get} the {@link SecurityKeyStore}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract interface AbstractSecurityGetKeyStore {

  /**
   * @return the {@link SecurityKeyStore}. May be {@code null}.
   */
  SecurityKeyStore getKeyStore();

  /**
   * @throws IllegalStateException if {@link #getKeyStore()} is {@code null}.
   * @return the {@link SecurityKeyStore}. Never {@code null}.
   */
  default SecurityKeyStore getKeyStoreRequired() {

    SecurityKeyStore keyStore = getKeyStore();
    if (keyStore == null) {
      throw new IllegalStateException("KeyStore is not available!");
    }
    return keyStore;
  }
}
