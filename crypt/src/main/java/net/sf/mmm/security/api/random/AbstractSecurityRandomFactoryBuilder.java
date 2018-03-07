package net.sf.mmm.security.api.random;

import net.sf.mmm.security.api.AbstractSecurityFactoryBuilder;
import net.sf.mmm.security.api.SecurityFactoryBuilder;

/**
 * Interface to {@link #random(SecurityRandomConfig) configure and build} a {@link SecurityRandomFactory}.
 *
 * @param <B> the return-type of the builder methods.
 * @see SecurityFactoryBuilder
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface AbstractSecurityRandomFactoryBuilder<B> extends AbstractSecurityFactoryBuilder {

  /**
   * @param configuration the {@link SecurityRandomConfig}.
   * @return the {@link SecurityRandomFactory} for the given {@code configuration}
   */
  SecurityRandomFactory random(SecurityRandomConfig configuration);

  /**
   * @param configuration the {@link SecurityRandomConfig}.
   * @return the {@link SecurityRandomFactory} for the given {@code configuration}
   */
  SecurityRandomFactory random();

}
