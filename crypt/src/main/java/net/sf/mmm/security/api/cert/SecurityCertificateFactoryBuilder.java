package net.sf.mmm.security.api.cert;

/**
 * This class ...
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityCertificateFactoryBuilder {

  /**
   * @param configuration the {@link SecurityCertificateConfig}.
   * @return the {@link SecurityCertificateCreator}.
   */
  SecurityCertificateCreator cert(SecurityCertificateConfig configuration);

}
