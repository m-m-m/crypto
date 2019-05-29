package net.sf.mmm.crypto.asymmetric.cert.access;

import net.sf.mmm.crypto.CryptoAccess;
import net.sf.mmm.crypto.asymmetric.cert.CertificateConfig;
import net.sf.mmm.crypto.asymmetric.cert.CertificateCreator;

/**
 * {@link CryptoAccess} for {@link CertificateCreator certificate management}.
 *
 * @since 1.0.0
 */
public abstract class CertificateAccess extends CryptoAccess {

  /** The {@link CertificateConfig} for the {@link CertificateConfig}. */
  protected final CertificateConfig config;

  /**
   * The constructor.
   *
   * @param config the {@link CertificateCreator}.
   */
  public CertificateAccess(CertificateConfig config) {

    super();
    this.config = config;
  }

  /**
   * @return a new instance of {@link CertificateCreator}.
   */
  public abstract CertificateCreator newCertificateCreator();

}
