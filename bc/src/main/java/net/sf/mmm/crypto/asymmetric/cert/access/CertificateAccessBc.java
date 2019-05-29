package net.sf.mmm.crypto.asymmetric.cert.access;

import net.sf.mmm.crypto.asymmetric.cert.CertificateConfig;
import net.sf.mmm.crypto.asymmetric.cert.CertificateCreator;
import net.sf.mmm.crypto.asymmetric.cert.CertificateCreatorImpl;
import net.sf.mmm.crypto.asymmetric.cert.access.CertificateAccess;

/**
 * {@link CertificateAccess} using {@link net.sf.mmm.crypto.provider.BouncyCastle} (as code dependency and
 * not necessarily as security provider).
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
