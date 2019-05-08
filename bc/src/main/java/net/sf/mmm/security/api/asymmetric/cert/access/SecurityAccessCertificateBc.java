package net.sf.mmm.security.api.asymmetric.cert.access;

import net.sf.mmm.security.api.asymmetric.cert.SecurityCertificateConfig;
import net.sf.mmm.security.api.asymmetric.cert.SecurityCertificateCreator;
import net.sf.mmm.security.api.asymmetric.cert.SecurityCertificateCreatorImpl;

/**
 * {@link SecurityAccessCertificate} using {@link net.sf.mmm.security.api.provider.BouncyCastle} (as code dependency and
 * not necessarily as security provider).
 *
 * @since 1.0.0
 */
public class SecurityAccessCertificateBc extends SecurityAccessCertificate {

  /**
   * The constructor.
   *
   * @param config the {@link SecurityCertificateConfig}.
   */
  public SecurityAccessCertificateBc(SecurityCertificateConfig config) {

    super(config);
  }

  @Override
  public SecurityCertificateCreator newCertificateCreator() {

    return new SecurityCertificateCreatorImpl(this.config);
  }

}
