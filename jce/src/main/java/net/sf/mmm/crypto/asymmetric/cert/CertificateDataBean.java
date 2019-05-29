package net.sf.mmm.crypto.asymmetric.cert;

import java.math.BigInteger;
import java.time.Instant;

/**
 * This class ...
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class CertificateDataBean implements CertificateData {

  private String subject;

  private String issuer;

  private Instant notBefore;

  private Instant notAfter;

  private BigInteger serialNumber;

  private String signatureAlgorithm;

  /**
   * The constructor.
   */
  public CertificateDataBean() {
    super();
  }

  @Override
  public Instant getNotBefore() {

    if (this.notBefore == null) {
      this.notBefore = Instant.now();
    }
    return this.notBefore;
  }

  /**
   * @param notBefore new value of {@link #getNotBefore()}.
   */
  public void setNotBefore(Instant notBefore) {

    this.notBefore = notBefore;
  }

  @Override
  public Instant getNotAfter() {

    return this.notAfter;
  }

  /**
   * @param notAfter new value of {@link #getNotAfter()}.
   */
  public void setNotAfter(Instant notAfter) {

    this.notAfter = notAfter;
  }

  @Override
  public String getIssuer() {

    return this.issuer;
  }

  /**
   * @param issuer new value of {@link #getIssuer()}.
   */
  public void setIssuer(String issuer) {

    this.issuer = issuer;
  }

  @Override
  public String getSubject() {

    return this.subject;
  }

  /**
   * @param subject new value of {@link #getSubject()}.
   */
  public void setSubject(String subject) {

    this.subject = subject;
  }

  @Override
  public BigInteger getSerialNumber() {

    if (this.serialNumber == null) {
      this.serialNumber = BigInteger.ONE;
    }
    return this.serialNumber;
  }

  /**
   * @param serialNumber new value of {@link #getSerialNumber()}.
   */
  public void setSerialNumber(BigInteger serialNumber) {

    this.serialNumber = serialNumber;
  }

  @Override
  public String getSignatureAlgorithm() {

    return this.signatureAlgorithm;
  }

  /**
   * @param signatureAlgorithm new value of {@link #getSignatureAlgorithm()}.
   */
  public void setSignatureAlgorithm(String signatureAlgorithm) {

    this.signatureAlgorithm = signatureAlgorithm;
  }

}
