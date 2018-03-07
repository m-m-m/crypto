package net.sf.mmm.security.api.cert;

import java.util.Objects;

/**
 * Configuration for {@link SecurityCertificateFactoryBuilder#cert(SecurityCertificateConfig)}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityCertificateConfig {

  private final String type;

  /**
   * The constructor.
   *
   * @param type the {@link #getType() type}.
   */
  public SecurityCertificateConfig(String type) {
    super();
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
