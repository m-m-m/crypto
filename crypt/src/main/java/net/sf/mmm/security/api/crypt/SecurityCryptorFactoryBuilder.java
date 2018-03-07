package net.sf.mmm.security.api.crypt;

import net.sf.mmm.security.api.AbstractSecurityFactoryBuilder;
import net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorConfigBidirectional;
import net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorConfigPrivatePublic;
import net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorConfigPublicPrivate;
import net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorFactoryBidirectional;
import net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorFactoryPrivatePublic;
import net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorFactoryPublicPrivate;
import net.sf.mmm.security.api.crypt.symmetric.SecuritySymmetricCryptorConfig;
import net.sf.mmm.security.api.crypt.symmetric.SecuritySymmetricCryptorFactory;

/**
 * Abstract interface to create a {@link SecurityCryptorFactory}.
 *
 * @see net.sf.mmm.security.api.SecurityBuilder
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract interface SecurityCryptorFactoryBuilder extends AbstractSecurityFactoryBuilder {

  /**
   * @param configuration the {@link SecurityCryptorConfig}.
   * @return the {@link SecurityCryptorFactory} for the given {@code configuration}
   */
  SecurityCryptorFactory cryptUnsafe(SecurityCryptorConfig<?> configuration);

  /**
   * @param configuration the {@link SecuritySymmetricCryptorConfig}.
   * @return the {@link SecuritySymmetricCryptorFactory} for the given {@code configuration}
   */
  SecuritySymmetricCryptorFactory crypt(SecuritySymmetricCryptorConfig configuration);

  /**
   * @param configuration the {@link SecurityAsymmetricCryptorConfigBidirectional}.
   * @return the {@link SecurityAsymmetricCryptorFactoryBidirectional} for the given {@code configuration}
   */
  SecurityAsymmetricCryptorFactoryBidirectional crypt(SecurityAsymmetricCryptorConfigBidirectional configuration);

  /**
   * @param configuration the {@link SecurityAsymmetricCryptorConfigPrivatePublic}.
   * @return the {@link SecurityAsymmetricCryptorFactoryPrivatePublic} for the given {@code configuration}
   */
  SecurityAsymmetricCryptorFactoryPrivatePublic crypt(SecurityAsymmetricCryptorConfigPrivatePublic configuration);

  /**
   * @param configuration the {@link SecurityAsymmetricCryptorConfigPublicPrivate}.
   * @return the {@link SecurityAsymmetricCryptorFactoryPublicPrivate} for the given {@code configuration}
   */
  SecurityAsymmetricCryptorFactoryPublicPrivate crypt(SecurityAsymmetricCryptorConfigPublicPrivate configuration);

}
