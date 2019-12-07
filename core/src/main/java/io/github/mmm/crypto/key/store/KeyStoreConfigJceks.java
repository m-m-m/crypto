package io.github.mmm.crypto.key.store;

import io.github.mmm.crypto.io.CryptoResource;

/**
 * {@link KeyStoreConfig} with {@link #getType() type} "JCEKS" (Java Cryptography Extension KeyStore). This is a
 * proprietary format specific for Java and requires JCE (Java Cryptography Extension) introduced in Java 1.4 with the
 * "SunJCE" {@link java.security.Provider}. It uses 3-DES (PBEWithMD5AndTripleDES) encryption and is therefore more
 * secure than JKS.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class KeyStoreConfigJceks extends KeyStoreConfig {

  /** The {@link #getType() type} {@value}. */
  public static final String TYPE = "JCEKS";

  /**
   * The constructor.
   *
   * @param resource the {@link #getResource() resource}.
   * @param password the {@link #getPassword() password}.
   */
  public KeyStoreConfigJceks(CryptoResource resource, String password) {
    super(TYPE, resource, password);
  }

}
