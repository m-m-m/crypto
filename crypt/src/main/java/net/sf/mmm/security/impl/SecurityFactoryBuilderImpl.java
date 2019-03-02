package net.sf.mmm.security.impl;

import java.security.Provider;

import net.sf.mmm.security.api.SecurityFactoryBuilder;
import net.sf.mmm.security.impl.cert.SecurityCertificateFactoryBuilderImpl;
import net.sf.mmm.security.impl.crypt.SecurityCryptorFactoryBuilderImpl;
import net.sf.mmm.security.impl.hash.SecurityHashFactoryBuilderImpl;
import net.sf.mmm.security.impl.key.SecurityKeyFactoryBuilderImpl;
import net.sf.mmm.security.impl.key.store.SecurityKeyStoreFactoryBuilderImpl;
import net.sf.mmm.security.impl.random.SecurityRandomFactoryBuilderImpl;
import net.sf.mmm.security.impl.sign.SecuritySignatureFactoryBuilderImpl;

/**
 * Implementation of {@link SecurityFactoryBuilder}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityFactoryBuilderImpl extends AbstractSecurityFactoriesMutableImpl
    implements SecurityFactoryBuilder, AbstractSecurityProviderBuilderImpl<SecurityFactoryBuilder>, SecurityRandomFactoryBuilderImpl,
    SecurityHashFactoryBuilderImpl, SecurityCryptorFactoryBuilderImpl, SecurityKeyFactoryBuilderImpl, SecuritySignatureFactoryBuilderImpl,
    SecurityKeyStoreFactoryBuilderImpl, SecurityCertificateFactoryBuilderImpl {

  /**
   * The constructor.
   */
  public SecurityFactoryBuilderImpl() {

    super();
  }

  @Override
  public SecurityFactoryBuilder provider(Provider provider) {

    setProvider(provider);
    return this;
  }

}
