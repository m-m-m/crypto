package io.github.mmm.crypto.asymmetric.cert;

import java.security.cert.Certificate;

import io.github.mmm.crypto.asymmetric.key.AsymmetricKeyPair;

/// Interface to [generate][#generateCertificate(AsymmetricKeyPair, CertificateData)] or
/// [deserialize][#createCertificate(byte[])] [Certificate]s as well to
/// [extract][#getCertificateData(Certificate)] [CertificateData] from a [Certificate].
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public interface CertificateCreator {

  /// @param certificate the [Certificate] as raw `byte` array.
  /// @return the deserialized [Certificate].
  Certificate createCertificate(byte[] certificate);

  /// @param keyPair the [AsymmetricKeyPair].
  /// @param certificateData the [CertificateData].
  /// @return the generated self-signed [Certificate].
  Certificate generateCertificate(AsymmetricKeyPair<?, ?> keyPair, CertificateData certificateData);

  /// @param certificate the [Certificate].
  /// @return the [CertificateData] with the meta-data from the certificate.
  CertificateData getCertificateData(Certificate certificate);
}
