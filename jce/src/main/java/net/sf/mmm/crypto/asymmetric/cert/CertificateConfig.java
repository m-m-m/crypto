package net.sf.mmm.crypto.asymmetric.cert;

import java.util.Objects;

import net.sf.mmm.crypto.CryptoConfig;
import net.sf.mmm.crypto.provider.SecurityProvider;

/**
 * Configuration for {@link CertificateCreator}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class CertificateConfig extends CryptoConfig {

  private final String type;

  /**
   * The constructor.
   *
   * @param type the {@link #getType() type}.
   * @param provider the {@link #getProvider() provider}.
   */
  public CertificateConfig(String type, SecurityProvider provider) {

    super(provider);
    Objects.requireNonNull(type, "type");
    this.type = type;
  }

  /**
   * @return type the {@link javax.security.cert.Certificate} {@link java.security.cert.CertificateFactory#getType()
   *         type}.
   */
  public String getType() {

    return this.type;
  }

}
