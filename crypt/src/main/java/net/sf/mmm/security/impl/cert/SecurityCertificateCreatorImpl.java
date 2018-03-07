package net.sf.mmm.security.impl.cert;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import net.sf.mmm.security.api.cert.SecurityCertificate;
import net.sf.mmm.security.api.cert.SecurityCertificateConfig;
import net.sf.mmm.security.api.cert.SecurityCertificateConfigX509;
import net.sf.mmm.security.api.cert.SecurityCertificateCreator;
import net.sf.mmm.security.api.cert.SecurityCertificateData;
import net.sf.mmm.security.api.cert.SecurityCertificateDataBean;
import net.sf.mmm.security.api.cert.SecurityCertificateGeneric;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyPair;
import net.sf.mmm.security.impl.AbstractSecurityAlgorithm;
import net.sf.mmm.security.impl.AbstractSecurityAlgorithmWithRandom;

/**
 * Implementation of {@link SecurityCertificateCreator}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityCertificateCreatorImpl extends AbstractSecurityAlgorithmWithRandom
    implements SecurityCertificateCreator {

  private final SecurityCertificateConfig config;

  private CertificateFactory certificateFactory;

  /**
   * The constructor.
   *
   * @param provider the optional security {@link Provider}.
   * @param config the {@link SecurityCertificateConfig}.
   */
  public SecurityCertificateCreatorImpl(Provider provider, SecurityCertificateConfig config) {
    super(provider, null);
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
      String type = this.config.getType();
      Provider provider = getProvider();
      try {
        if (provider == null) {
          this.certificateFactory = CertificateFactory.getInstance(type);
        } else {
          this.certificateFactory = CertificateFactory.getInstance(type, provider);
        }
      } catch (Exception e) {
        throw creationFailedException(e, CertificateFactory.class, type);
      }
    }
    return this.certificateFactory;
  }

  @Override
  public SecurityCertificate createCertificate(byte[] certificate) {

    ByteArrayInputStream in = new ByteArrayInputStream(certificate);
    Certificate cert;
    try {
      cert = getCertificateFactory().generateCertificate(in);
    } catch (Exception e) {
      throw creationFailedException(e, Certificate.class);
    }
    return new SecurityCertificateGeneric(certificate, cert);
  }

  @Override
  public SecurityCertificate generateCertificate(SecurityAsymmetricKeyPair keyPair,
      SecurityCertificateData certificateData) {

    // TODO
    // https://stackoverflow.com/questions/9938079/generating-x509certificate-using-bouncycastle-x509v3certificatebuilder
    String type = this.config.getType();
    if (!type.equals(SecurityCertificateConfigX509.TYPE_X509)) {
      throw new UnsupportedOperationException("Unsupported certificate type: " + type);
    }
    try {
      PublicKey publicKey = keyPair.getPublicKey().getKey();
      PrivateKey privateKey = keyPair.getPrivateKey().getKey();
      SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
      X500Name subject = new X500Name(certificateData.getSubject());
      Date notAfter = Date.from(certificateData.getNotAfter());
      Date notBefore = Date.from(certificateData.getNotBefore());
      X500Name issuer = new X500Name(certificateData.getIssuer());
      BigInteger serial = certificateData.getSerialNumber();
      X509v3CertificateBuilder builder =
          new X509v3CertificateBuilder(issuer, serial, notBefore, notAfter, subject, publicKeyInfo);
      ContentSigner signer = new JcaContentSignerBuilder(certificateData.getSignatureAlgorithm()).build(privateKey);
      X509CertificateHolder certificateHolder = builder.build(signer);
      X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certificateHolder);
      return new SecurityCertificateGeneric(certificate);
    } catch (Exception e) {
      throw AbstractSecurityAlgorithm.creationFailedException(e, Certificate.class, type);
    }
  }

  @Override
  public SecurityCertificateData getCertificateData(SecurityCertificate certificate) {

    Certificate cert = certificate.getCertificate();
    if (cert instanceof X509Certificate) {
      X509Certificate x509Certificate = (X509Certificate) cert;
      SecurityCertificateDataBean dataBean = new SecurityCertificateDataBean();
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
      throw new UnsupportedOperationException("Unsupported certificate type: " + cert.getType());
    }
  }

}
