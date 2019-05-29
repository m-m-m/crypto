package net.sf.mmm.crypto.key.store.access;

import java.io.File;

import net.sf.mmm.crypto.io.CryptoResource;
import net.sf.mmm.crypto.io.CryptoFileResource;
import net.sf.mmm.crypto.key.store.KeyStoreConfigPkcs12;

/**
 * {@link KeyStoreAccess} for {@link KeyStoreConfigPkcs12 PKCS#12}.
 *
 * @since 1.0.0
 */
public class KeyStoreAccessPkcs12 extends KeyStoreAccess {

  /**
   * The constructor.
   *
   * @param config the {@link KeyStoreConfigPkcs12}.
   */
  public KeyStoreAccessPkcs12(KeyStoreConfigPkcs12 config) {

    super(config);
  }

  /**
   * @param keyStore the {@link File} pointing to the keystore.
   * @param password the password used to encrypt/decrypt the keystore.
   * @return the new instance.
   */
  public static KeyStoreAccessPkcs12 of(File keyStore, String password) {

    return of(new CryptoFileResource(keyStore), password);
  }

  /**
   * @param keyStoreResource the {@link CryptoResource} pointing to the keystore.
   * @param password the password used to encrypt/decrypt the keystore.
   * @return the new instance.
   */
  public static KeyStoreAccessPkcs12 of(CryptoResource keyStoreResource, String password) {

    return new KeyStoreAccessPkcs12(new KeyStoreConfigPkcs12(keyStoreResource, password));
  }

}
