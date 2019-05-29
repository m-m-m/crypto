package net.sf.mmm.crypto;

import net.sf.mmm.crypto.provider.SecurityProvider;

/**
 * Abstract base class for a configuration of a security creator or processor (for hashes, signatures, keys, encryption,
 * decryption, etc.). It {@link #getProvider() configures} the {@link SecurityProvider} used for fabrication.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class CryptoConfig {

  /** @see #getProvider() */
  protected final SecurityProvider provider;

  /**
   * The constructor.
   *
   * @param provider the {@link #getProvider() provider}.
   */
  public CryptoConfig(SecurityProvider provider) {

    super();
    if (provider == null) {
      this.provider = SecurityProvider.DEFAULT;
    } else {
      this.provider = provider;
    }
  }

  /**
   * @return the {@link SecurityProvider}.
   */
  public SecurityProvider getProvider() {

    return this.provider;
  }

}
