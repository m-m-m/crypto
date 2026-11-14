package io.github.mmm.crypto.asymmetric.cert.access;

import io.github.mmm.crypto.CryptoAccess;
import io.github.mmm.crypto.asymmetric.cert.CertificateConfig;
import io.github.mmm.crypto.asymmetric.cert.CertificateCreator;

/// [CryptoAccess] for [certificate management][CertificateCreator].
///
/// @since 1.0.0
public abstract class CertificateAccess extends CryptoAccess {

  /// The [CertificateConfig] for the [CertificateConfig].
  protected final CertificateConfig config;

  /// The constructor.
  ///
  /// @param config the [CertificateCreator].
  public CertificateAccess(CertificateConfig config) {

    super();
    this.config = config;
  }

  /// @return a new instance of [CertificateCreator].
  public abstract CertificateCreator newCertificateCreator();

}
