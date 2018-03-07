package net.sf.mmm.security.impl.crypt.asymmetric;

import java.security.Provider;

import net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorConfigPrivatePublic;
import net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorFactoryBidirectional;
import net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorFactoryPrivatePublic;
import net.sf.mmm.security.api.random.SecurityRandomFactory;
import net.sf.mmm.security.impl.crypt.SecurityCryptorFactoryImpl;

/**
 * Implementation of {@link SecurityAsymmetricCryptorFactoryBidirectional}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityAsymmetricCryptorFactoryPrivatePublicImpl extends SecurityCryptorFactoryImpl
    implements SecurityAsymmetricCryptorFactoryPrivatePublic {

  /**
   * The constructor.
   *
   * @param config the {@link SecurityAsymmetricCryptorConfigPrivatePublic}.
   * @param provider the security {@link Provider}.
   * @param randomFactory the {@link SecurityRandomFactory}.
   */
  public SecurityAsymmetricCryptorFactoryPrivatePublicImpl(SecurityAsymmetricCryptorConfigPrivatePublic config,
      Provider provider, SecurityRandomFactory randomFactory) {

    super(config, provider, randomFactory);
  }

}
