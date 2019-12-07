package io.github.mmm.crypto.asymmetric.cert.access.bc;

import io.github.mmm.crypto.asymmetric.cert.CertificateConfigX509;
import io.github.mmm.crypto.asymmetric.cert.access.CertificateAccess;
import io.github.mmm.crypto.provider.SecurityProvider;

/**
 * {@link CertificateAccess} for {@link CertificateConfigX509 X.509}.
 *
 * @since 1.0.0
 */
public class CertificateAccessX509 extends CertificateAccessBc {

  /**
   * The constructor.
   *
   * @param config the {@link CertificateConfigX509}.
   */
  public CertificateAccessX509(CertificateConfigX509 config) {

    super(config);
  }

  /**
   * @return a new default instance of {@link CertificateAccessX509}.
   */
  public static CertificateAccessX509 of() {

    return new CertificateAccessX509(new CertificateConfigX509());
  }

  /**
   * @return a new default instance of {@link CertificateAccessX509}.
   * @param provider the {@link SecurityProvider} to use.
   */
  public static CertificateAccessX509 of(SecurityProvider provider) {

    return new CertificateAccessX509(new CertificateConfigX509(provider));
  }

}
