package net.sf.mmm.crypto.asymmetric.cert;

import java.security.cert.Certificate;

import net.sf.mmm.crypto.asymmetric.key.AsymmetricKeyPair;

/**
 * Interface to {@link #generateCertificate(AsymmetricKeyPair, CertificateData) generate} or
 * {@link #createCertificate(byte[]) deserialize} {@link Certificate}s as well to
 * {@link #getCertificateData(Certificate) extract} {@link CertificateData} from a {@link Certificate}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface CertificateCreator {

  /**
   * @param certificate the {@link Certificate} as raw {@code byte} array.
   * @return the deserialized {@link Certificate}.
   */
  Certificate createCertificate(byte[] certificate);

  /**
   * @param keyPair the {@link AsymmetricKeyPair}.
   * @param certificateData the {@link CertificateData}.
   * @return the generated self-signed {@link Certificate}.
   */
  Certificate generateCertificate(AsymmetricKeyPair<?, ?> keyPair, CertificateData certificateData);

  /**
   * @param certificate the {@link Certificate}.
   * @return the {@link CertificateData} with the meta-data from the certificate.
   */
  CertificateData getCertificateData(Certificate certificate);
}
