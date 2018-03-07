package net.sf.mmm.security.impl.cert;

import net.sf.mmm.security.api.cert.SecurityCertificateConfig;
import net.sf.mmm.security.api.cert.SecurityCertificateCreator;
import net.sf.mmm.security.api.cert.SecurityCertificateFactoryBuilder;
import net.sf.mmm.security.api.provider.AbstractSecurityGetProvider;

/**
 * Implementation of {@link SecurityCertificateFactoryBuilder}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityCertificateFactoryBuilderImpl extends SecurityCertificateFactoryBuilder, AbstractSecurityGetProvider {

  @Override
  default SecurityCertificateCreator cert(SecurityCertificateConfig configuration) {

    return new SecurityCertificateCreatorImpl(getProvider(), configuration);
  }

}
