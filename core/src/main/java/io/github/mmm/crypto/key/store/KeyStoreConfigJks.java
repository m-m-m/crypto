package io.github.mmm.crypto.key.store;

import io.github.mmm.crypto.io.CryptoResource;

/**
 * {@link KeyStoreConfig} with {@link #getType() type} "JKS" (Java KeyStore). This is a proprietary format
 * specific for Java and was the initial default. It has limitations and can not store {@link javax.crypto.SecretKey}s.
 * For details see also <a href="http://metastatic.org/source/JKS.html">JKS</a>
 *
 * @deprecated JKS uses weak encryption so other formats should be preferred. Still the best protection of private keys
 *             is to ensure they can never leave your computer. However, in the days of Internet connection and cyber
 *             crime this can not be guaranteed. Therefore, strong encryption and long passwords help to prevent
 *             disasters.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
@Deprecated
public class KeyStoreConfigJks extends KeyStoreConfig {

  /** The {@link #getType() type} {@value}. */
  public static final String TYPE = "JKS";

  /**
   * The constructor.
   *
   * @param resource the {@link #getResource() resource}.
   * @param password the {@link #getPassword() password}.
   */
  public KeyStoreConfigJks(CryptoResource resource, String password) {
    super(TYPE, resource, password);
  }

}
