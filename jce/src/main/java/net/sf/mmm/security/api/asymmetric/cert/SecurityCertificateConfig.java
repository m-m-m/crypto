package net.sf.mmm.security.api.asymmetric.cert;

import java.util.Objects;

import net.sf.mmm.security.api.SecurityConfig;
import net.sf.mmm.security.api.provider.SecurityProvider;

/**
 * Configuration for {@link SecurityCertificateCreator}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityCertificateConfig extends SecurityConfig {

  private final String type;

  /**
   * The constructor.
   *
   * @param type the {@link #getType() type}.
   * @param provider the {@link #getProvider() provider}.
   */
  public SecurityCertificateConfig(String type, SecurityProvider provider) {

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
