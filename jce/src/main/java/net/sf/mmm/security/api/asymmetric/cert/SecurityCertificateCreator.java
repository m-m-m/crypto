package net.sf.mmm.security.api.asymmetric.cert;

import java.security.cert.Certificate;

import net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyPair;

/**
 * Interface to {@link #generateCertificate(SecurityAsymmetricKeyPair, SecurityCertificateData) generate} or
 * {@link #createCertificate(byte[]) deserialize} {@link Certificate}s as well to
 * {@link #getCertificateData(Certificate) extract} {@link SecurityCertificateData} from a {@link Certificate}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityCertificateCreator {

  /**
   * @param certificate the {@link Certificate} as raw {@code byte} array.
   * @return the deserialized {@link Certificate}.
   */
  Certificate createCertificate(byte[] certificate);

  /**
   * @param keyPair the {@link SecurityAsymmetricKeyPair}.
   * @param certificateData the {@link SecurityCertificateData}.
   * @return the generated self-signed {@link Certificate}.
   */
  Certificate generateCertificate(SecurityAsymmetricKeyPair<?, ?> keyPair, SecurityCertificateData certificateData);

  /**
   * @param certificate the {@link Certificate}.
   * @return the {@link SecurityCertificateData} with the meta-data from the certificate.
   */
  SecurityCertificateData getCertificateData(Certificate certificate);
}
