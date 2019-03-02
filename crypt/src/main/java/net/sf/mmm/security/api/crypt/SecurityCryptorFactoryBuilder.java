package net.sf.mmm.security.api.crypt;

import net.sf.mmm.security.api.AbstractSecurityFactoryBuilder;
import net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorConfig;
import net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorFactory;
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
   * @param configuration the {@link SecurityAsymmetricCryptorConfig}.
   * @return the {@link SecurityAsymmetricCryptorFactory} for the given {@code configuration}
   */
  SecurityAsymmetricCryptorFactory crypt(SecurityAsymmetricCryptorConfig configuration);

}
