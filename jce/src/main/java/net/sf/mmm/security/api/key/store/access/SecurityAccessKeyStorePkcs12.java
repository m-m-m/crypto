package net.sf.mmm.security.api.key.store.access;

import java.io.File;

import net.sf.mmm.security.api.io.SecurityDataResource;
import net.sf.mmm.security.api.io.SecurityFileResource;
import net.sf.mmm.security.api.key.store.SecurityKeyStoreConfigPkcs12;

/**
 * {@link SecurityAccessKeyStore} for {@link SecurityKeyStoreConfigPkcs12 PKCS#12}.
 *
 * @since 1.0.0
 */
public class SecurityAccessKeyStorePkcs12 extends SecurityAccessKeyStore {

  /**
   * The constructor.
   *
   * @param config the {@link SecurityKeyStoreConfigPkcs12}.
   */
  public SecurityAccessKeyStorePkcs12(SecurityKeyStoreConfigPkcs12 config) {

    super(config);
  }

  /**
   * @param keyStore the {@link File} pointing to the keystore.
   * @param password the password used to encrypt/decrypt the keystore.
   * @return the new instance.
   */
  public static SecurityAccessKeyStorePkcs12 of(File keyStore, String password) {

    return of(new SecurityFileResource(keyStore), password);
  }

  /**
   * @param keyStoreResource the {@link SecurityDataResource} pointing to the keystore.
   * @param password the password used to encrypt/decrypt the keystore.
   * @return the new instance.
   */
  public static SecurityAccessKeyStorePkcs12 of(SecurityDataResource keyStoreResource, String password) {

    return new SecurityAccessKeyStorePkcs12(new SecurityKeyStoreConfigPkcs12(keyStoreResource, password));
  }

}
