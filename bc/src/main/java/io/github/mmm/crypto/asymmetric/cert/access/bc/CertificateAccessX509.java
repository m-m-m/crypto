package io.github.mmm.crypto.asymmetric.cert.access.bc;

import io.github.mmm.crypto.asymmetric.cert.CertificateConfigX509;
import io.github.mmm.crypto.asymmetric.cert.access.CertificateAccess;
import io.github.mmm.crypto.provider.SecurityProvider;

/// [CertificateAccess] for [X.509][CertificateConfigX509].
///
/// @since 1.0.0
public class CertificateAccessX509 extends CertificateAccessBc {

  /// The constructor.
  ///
  /// @param config the [CertificateConfigX509].
  public CertificateAccessX509(CertificateConfigX509 config) {

    super(config);
  }

  /// @return a new default instance of [CertificateAccessX509].
  public static CertificateAccessX509 of() {

    return new CertificateAccessX509(new CertificateConfigX509());
  }

  /// @return a new default instance of [CertificateAccessX509].
  /// @param provider the [SecurityProvider] to use.
  public static CertificateAccessX509 of(SecurityProvider provider) {

    return new CertificateAccessX509(new CertificateConfigX509(provider));
  }

}
