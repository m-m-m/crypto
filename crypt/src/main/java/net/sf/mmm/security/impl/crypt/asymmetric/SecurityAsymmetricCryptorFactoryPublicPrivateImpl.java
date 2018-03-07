package net.sf.mmm.security.impl.crypt.asymmetric;

import java.security.Provider;

import net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorConfigPublicPrivate;
import net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorFactoryPublicPrivate;
import net.sf.mmm.security.api.random.SecurityRandomFactory;
import net.sf.mmm.security.impl.crypt.SecurityCryptorFactoryImpl;

/**
 * Implementation of {@link SecurityAsymmetricCryptorFactoryPublicPrivate}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityAsymmetricCryptorFactoryPublicPrivateImpl extends SecurityCryptorFactoryImpl
    implements SecurityAsymmetricCryptorFactoryPublicPrivate {

  /**
   * The constructor.
   *
   * @param config the {@link SecurityAsymmetricCryptorConfigPublicPrivate}.
   * @param provider the security {@link Provider}.
   * @param randomFactory the {@link SecurityRandomFactory}.
   */
  public SecurityAsymmetricCryptorFactoryPublicPrivateImpl(SecurityAsymmetricCryptorConfigPublicPrivate config,
      Provider provider, SecurityRandomFactory randomFactory) {

    super(config, provider, randomFactory);
  }

}
