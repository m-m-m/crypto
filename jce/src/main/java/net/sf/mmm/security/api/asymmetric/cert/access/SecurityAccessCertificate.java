package net.sf.mmm.security.api.asymmetric.cert.access;

import net.sf.mmm.security.api.SecurityAccess;
import net.sf.mmm.security.api.asymmetric.cert.SecurityCertificateConfig;
import net.sf.mmm.security.api.asymmetric.cert.SecurityCertificateCreator;

/**
 * {@link SecurityAccess} for {@link SecurityCertificateCreator certificate management}.
 *
 * @since 1.0.0
 */
public abstract class SecurityAccessCertificate extends SecurityAccess {

  /** The {@link SecurityCertificateConfig} for the {@link SecurityCertificateConfig}. */
  protected final SecurityCertificateConfig config;

  /**
   * The constructor.
   *
   * @param config the {@link SecurityCertificateCreator}.
   */
  public SecurityAccessCertificate(SecurityCertificateConfig config) {

    super();
    this.config = config;
  }

  /**
   * @return a new instance of {@link SecurityCertificateCreator}.
   */
  public abstract SecurityCertificateCreator newCertificateCreator();

}
