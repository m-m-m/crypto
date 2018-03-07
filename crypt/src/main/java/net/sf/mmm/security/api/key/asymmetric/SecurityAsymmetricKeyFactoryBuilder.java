package net.sf.mmm.security.api.key.asymmetric;

import net.sf.mmm.security.api.AbstractSecurityFactoryBuilder;

/**
 * Abstract interface to {@link #key(SecurityAsymmetricKeyConfig) configure and build} a
 * {@link SecurityAsymmetricKeyFactory}.
 *
 * @see net.sf.mmm.security.api.SecurityBuilder
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract interface SecurityAsymmetricKeyFactoryBuilder extends AbstractSecurityFactoryBuilder {

  /**
   * @param configuration the {@link SecurityAsymmetricKeyConfig}.
   * @return the {@link SecurityAsymmetricKeyFactory} for the given {@code configuration}
   */
  SecurityAsymmetricKeyFactory key(SecurityAsymmetricKeyConfig configuration);

}
