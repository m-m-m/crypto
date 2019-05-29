package net.sf.mmm.crypto.asymmetric.cert;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.time.Instant;

import net.sf.mmm.crypto.algorithm.CryptoAlgorithm;

/**
 * Interface for the meta-data of a {@link java.security.cert.Certificate}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface CertificateData {

  /**
   * @return the issuer of the certificate.
   */
  String getIssuer();

  /**
   * @return the subject of the certificate (e.g. "CN=myname@mydomain.com").
   */
  String getSubject();

  /**
   * @return the serial number (e.g. {@link BigInteger#ONE}).
   */
  BigInteger getSerialNumber();

  /**
   * @return the begin of the validity.
   * @see X509Certificate#getNotBefore()
   */
  Instant getNotBefore();

  /**
   * @return the end of the validity.
   * @see X509Certificate#getNotAfter()
   */
  Instant getNotAfter();

  /**
   * @return the {@link CryptoAlgorithm#getAlgorithm() algorithm name} for the signature.
   */
  String getSignatureAlgorithm();

}
