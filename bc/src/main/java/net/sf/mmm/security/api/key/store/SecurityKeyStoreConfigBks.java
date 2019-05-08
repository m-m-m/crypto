package net.sf.mmm.security.api.key.store;

import net.sf.mmm.security.api.io.SecurityDataResource;
import net.sf.mmm.security.api.provider.BouncyCastle;
import net.sf.mmm.security.api.provider.SecurityProvider;

/**
 * {@link SecurityKeyStoreConfig} with {@link #getType() type} "BKS" (Bouncycaste KeyStore). This is a proprietary
 * format from the popular third party Java cryptographic library provider
 * <a href="https://bouncycastle.org/">BouncyCastle</a>.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityKeyStoreConfigBks extends SecurityKeyStoreConfig {

  /** The {@link #getType() type} {@value}. */
  public static final String TYPE = "BKS";

  /**
   * The constructor.
   *
   * @param resource the {@link #getResource() resource}.
   * @param password the {@link #getPassword() password}.
   */
  public SecurityKeyStoreConfigBks(SecurityDataResource resource, String password) {

    super(TYPE, SecurityProvider.of(BouncyCastle.getProvider()), resource, password);
  }

}
