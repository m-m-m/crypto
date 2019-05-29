package net.sf.mmm.crypto.key.store;

import net.sf.mmm.crypto.io.CryptoResource;
import net.sf.mmm.crypto.key.store.KeyStoreConfig;
import net.sf.mmm.crypto.provider.BouncyCastle;
import net.sf.mmm.crypto.provider.SecurityProvider;

/**
 * {@link KeyStoreConfig} with {@link #getType() type} "BKS" (Bouncycaste KeyStore). This is a proprietary
 * format from the popular third party Java cryptographic library provider
 * <a href="https://bouncycastle.org/">BouncyCastle</a>.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class KeyStoreConfigBks extends KeyStoreConfig {

  /** The {@link #getType() type} {@value}. */
  public static final String TYPE = "BKS";

  /**
   * The constructor.
   *
   * @param resource the {@link #getResource() resource}.
   * @param password the {@link #getPassword() password}.
   */
  public KeyStoreConfigBks(CryptoResource resource, String password) {

    super(TYPE, SecurityProvider.of(BouncyCastle.getProvider()), resource, password);
  }

}
