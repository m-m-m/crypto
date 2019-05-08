package net.sf.mmm.security.api.asymmetric.cert.access;

import net.sf.mmm.security.api.asymmetric.cert.SecurityCertificateConfigX509;
import net.sf.mmm.security.api.provider.SecurityProvider;

/**
 * {@link SecurityAccessCertificate} for {@link SecurityCertificateConfigX509 X.509}.
 *
 * @since 1.0.0
 */
public class SecurityAccessCertificateX509 extends SecurityAccessCertificateBc {

  /**
   * The constructor.
   *
   * @param config the {@link SecurityCertificateConfigX509}.
   */
  public SecurityAccessCertificateX509(SecurityCertificateConfigX509 config) {

    super(config);
  }

  /**
   * @return a new default instance of {@link SecurityAccessCertificateX509}.
   */
  public static SecurityAccessCertificateX509 of() {

    return new SecurityAccessCertificateX509(new SecurityCertificateConfigX509());
  }

  /**
   * @return a new default instance of {@link SecurityAccessCertificateX509}.
   * @param provider the {@link SecurityProvider} to use.
   */
  public static SecurityAccessCertificateX509 of(SecurityProvider provider) {

    return new SecurityAccessCertificateX509(new SecurityCertificateConfigX509(provider));
  }

}
