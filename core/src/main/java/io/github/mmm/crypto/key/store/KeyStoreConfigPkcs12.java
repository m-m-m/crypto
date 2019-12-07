package io.github.mmm.crypto.key.store;

import io.github.mmm.crypto.io.CryptoResource;

/**
 * {@link KeyStoreConfig} with {@link #getType() type} "PKCS12" (Public-Key Cryptography Standards #12). For
 * details see <a href="https://en.wikipedia.org/wiki/PKCS_12">PKCS#12</a>. PKCS#12 is a quite complex and generic
 * format. It allows to define the encryption via an "AlgorithmIdentifier" so
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class KeyStoreConfigPkcs12 extends KeyStoreConfig {

  /** The {@link #getType() type} {@value}. */
  public static final String TYPE = "PKCS12";

  /**
   * The constructor.
   *
   * @param resource the {@link #getResource() resource}.
   * @param password the {@link #getPassword() password}.
   */
  public KeyStoreConfigPkcs12(CryptoResource resource, String password) {
    super(TYPE, resource, password);
  }

  @Override
  public String getExtension() {

    return ".p12";
  }

}
