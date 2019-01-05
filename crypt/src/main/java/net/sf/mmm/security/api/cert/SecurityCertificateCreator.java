package net.sf.mmm.security.api.cert;

import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyPair;
import net.sf.mmm.util.datatype.api.BinaryType;

/**
 * Interface to {@link #generateCertificate(SecurityAsymmetricKeyPair, SecurityCertificateData) generate} or
 * {@link #createCertificate(byte[]) deserialize} {@link SecurityCertificate}s as well to
 * {@link #getCertificateData(SecurityCertificate) extract} {@link SecurityCertificateData} from a
 * {@link SecurityCertificate}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityCertificateCreator {

  /**
   * @param certificate the {@link SecurityCertificate} as raw {@code byte} array.
   * @return the deserialized {@link SecurityCertificate}.
   */
  SecurityCertificate createCertificate(byte[] certificate);

  /**
   * @param certificate the {@link SecurityCertificate} in {@link BinaryType#getHex() hex representation}.
   * @return the deserialized {@link SecurityCertificate}.
   */
  default SecurityCertificate createCertificate(String certificate) {

    return createCertificate(BinaryType.parseHex(certificate));
  }

  /**
   * @param keyPair the {@link SecurityAsymmetricKeyPair}.
   * @param certificateData the {@link SecurityCertificateData}.
   * @return the generated self-signed {@link SecurityCertificate}.
   */
  SecurityCertificate generateCertificate(SecurityAsymmetricKeyPair keyPair, SecurityCertificateData certificateData);

  /**
   * @param certificate the {@link SecurityCertificate}.
   * @return the {@link SecurityCertificateData} with the meta-data from the certificate.
   */
  SecurityCertificateData getCertificateData(SecurityCertificate certificate);
}
