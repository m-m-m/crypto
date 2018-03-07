package net.sf.mmm.security.api.hash;

import net.sf.mmm.security.api.AbstractSecurityFactoryBuilder;

/**
 * Interface to {@link #hash(SecurityHashConfig) create} a {@link SecurityHashFactory}.
 *
 * @see net.sf.mmm.security.api.SecurityFactoryBuilder
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityHashFactoryBuilder extends AbstractSecurityFactoryBuilder {

  /**
   * @param configuration the {@link SecurityHashConfig}.
   * @return the {@link SecurityHashFactory} for the given {@code configuration}
   */
  SecurityHashFactory hash(SecurityHashConfig configuration);

}
