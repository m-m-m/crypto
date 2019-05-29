package net.sf.mmm.crypto.asymmetric.cert;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import net.sf.mmm.crypto.algorithm.AbstractSecurityAlgorithm;
import net.sf.mmm.crypto.asymmetric.cert.CertificateConfig;
import net.sf.mmm.crypto.asymmetric.cert.CertificateConfigX509;
import net.sf.mmm.crypto.asymmetric.cert.CertificateCreator;
import net.sf.mmm.crypto.asymmetric.cert.CertificateData;
import net.sf.mmm.crypto.asymmetric.cert.CertificateDataBean;
import net.sf.mmm.crypto.asymmetric.key.AsymmetricKeyPair;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Implementation of {@link CertificateCreator}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class CertificateCreatorImpl extends AbstractSecurityAlgorithm implements CertificateCreator {

  private final CertificateConfig config;

  private CertificateFactory certificateFactory;

  /**
   * The constructor.
   *
   * @param config the {@link CertificateConfig}.
   */
  public CertificateCreatorImpl(CertificateConfig config) {

    super();
    this.config = config;
  }

  @Override
  public String getAlgorithm() {

    return this.config.getType();
  }

  /**
   * @return the {@link CertificateFactory}.
   */
  protected CertificateFactory getCertificateFactory() {

    if (this.certificateFactory == null) {
      this.certificateFactory = this.config.getProvider().createCertificateFactory(this.config.getType());
    }
    return this.certificateFactory;
  }

  @Override
  public Certificate createCertificate(byte[] certificateData) {

    ByteArrayInputStream in = new ByteArrayInputStream(certificateData);
    Certificate certificate;
    try {
      certificate = getCertificateFactory().generateCertificate(in);
    } catch (Exception e) {
      throw creationFailedException(e, Certificate.class);
    }
    return certificate;
  }

  @Override
  public Certificate generateCertificate(AsymmetricKeyPair<?, ?> keyPair, CertificateData certificateData) {

    // TODO
    // https://stackoverflow.com/questions/9938079/generating-x509certificate-using-bouncycastle-x509v3certificatebuilder
    String type = this.config.getType();
    if (!type.equals(CertificateConfigX509.TYPE_X509)) {
      throw new UnsupportedOperationException("Unsupported certificate type: " + type);
    }
    try {
      PublicKey publicKey = keyPair.getPublicKey();
      PrivateKey privateKey = keyPair.getPrivateKey();
      SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
      X500Name subject = new X500Name(certificateData.getSubject());
      Date notAfter = Date.from(certificateData.getNotAfter());
      Date notBefore = Date.from(certificateData.getNotBefore());
      X500Name issuer = new X500Name(certificateData.getIssuer());
      BigInteger serial = certificateData.getSerialNumber();
      X509v3CertificateBuilder builder = new X509v3CertificateBuilder(issuer, serial, notBefore, notAfter, subject, publicKeyInfo);
      ContentSigner signer = new JcaContentSignerBuilder(certificateData.getSignatureAlgorithm()).build(privateKey);
      X509CertificateHolder certificateHolder = builder.build(signer);
      X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certificateHolder);
      return certificate;
    } catch (Exception e) {
      throw AbstractSecurityAlgorithm.creationFailedException(e, Certificate.class, type);
    }
  }

  @Override
  public CertificateData getCertificateData(Certificate certificate) {

    if (certificate instanceof X509Certificate) {
      X509Certificate x509Certificate = (X509Certificate) certificate;
      CertificateDataBean dataBean = new CertificateDataBean();
      Date notAfter = x509Certificate.getNotAfter();
      if (notAfter != null) {
        dataBean.setNotAfter(notAfter.toInstant());
      }
      Date notBefore = x509Certificate.getNotBefore();
      if (notBefore != null) {
        dataBean.setNotBefore(notBefore.toInstant());
      }
      X500Principal issuer = x509Certificate.getIssuerX500Principal();
      if (issuer != null) {
        dataBean.setIssuer(issuer.getName());
      }
      Principal subject = x509Certificate.getSubjectX500Principal();
      if (subject != null) {
        dataBean.setSubject(subject.getName());
      }
      BigInteger serialNumber = x509Certificate.getSerialNumber();
      if (serialNumber != null) {
        dataBean.setSerialNumber(serialNumber);
      }
      String signatureAlgorithmName = x509Certificate.getSigAlgName();
      if (signatureAlgorithmName != null) {
        dataBean.setSignatureAlgorithm(signatureAlgorithmName);
      }
      return dataBean;
    } else {
      throw new UnsupportedOperationException("Unsupported certificate type: " + certificate.getType());
    }
  }

}
