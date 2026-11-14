package io.github.mmm.crypto.asymmetric.cert;

import java.util.Objects;

import io.github.mmm.crypto.CryptoConfig;
import io.github.mmm.crypto.provider.SecurityProvider;

/// Configuration for [CertificateCreator].
///
/// @since 1.0.0
public class CertificateConfig extends CryptoConfig {

  private final String type;

  /// The constructor.
  ///
  /// @param type the [type][#getType()].
  /// @param provider the [provider][#getProvider()].
  public CertificateConfig(String type, SecurityProvider provider) {

    super(provider);
    Objects.requireNonNull(type, "type");
    this.type = type;
  }

  /// @return type the [java.security.cert.Certificate] [type][java.security.cert.CertificateFactory#getType()].
  public String getType() {

    return this.type;
  }

}
