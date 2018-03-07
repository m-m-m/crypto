package net.sf.mmm.security.api.key.symmetric;

import net.sf.mmm.security.api.AbstractSecurityFactoryBuilder;

/**
 * Abstract interface to {@link #key(SecuritySymmetricKeyConfig) configure and build} a
 * {@link SecuritySymmetricKeyFactory}.
 *
 * @see net.sf.mmm.security.api.SecurityBuilder
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract interface SecuritySymmetricKeyFactoryBuilder extends AbstractSecurityFactoryBuilder {

  /**
   * @param configuration the {@link SecuritySymmetricKeyConfig}.
   * @return the {@link SecuritySymmetricKeyFactory} for the given {@code configuration}
   */
  SecuritySymmetricKeyFactory key(SecuritySymmetricKeyConfig configuration);

}
