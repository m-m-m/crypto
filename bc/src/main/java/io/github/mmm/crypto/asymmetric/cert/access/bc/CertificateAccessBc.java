package io.github.mmm.crypto.asymmetric.cert.access.bc;

import io.github.mmm.crypto.asymmetric.cert.CertificateConfig;
import io.github.mmm.crypto.asymmetric.cert.CertificateCreator;
import io.github.mmm.crypto.asymmetric.cert.access.CertificateAccess;
import io.github.mmm.crypto.asymmetric.cert.bc.CertificateCreatorImpl;

/**
 * {@link CertificateAccess} using {@link io.github.mmm.crypto.provider.bc.BouncyCastle} (as code dependency and not
 * necessarily as security provider).
 *
 * @since 1.0.0
 */
public class CertificateAccessBc extends CertificateAccess {

  /**
   * The constructor.
   *
   * @param config the {@link CertificateConfig}.
   */
  public CertificateAccessBc(CertificateConfig config) {

    super(config);
  }

  @Override
  public CertificateCreator newCertificateCreator() {

    return new CertificateCreatorImpl(this.config);
  }

}
