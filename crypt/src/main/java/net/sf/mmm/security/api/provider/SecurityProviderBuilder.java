package net.sf.mmm.security.api.provider;

import java.security.Provider;

/**
 * Abstract interface to build security {@link Provider}.
 *
 * @see net.sf.mmm.security.api.SecurityFactoryBuilder
 * @param <B> type of the returned builder.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract interface SecurityProviderBuilder<B> extends SecurityProviderConstants {

  /**
   * Use default (no explicit {@link Provider} but ask all {@link java.security.Security#getProviders() available
   * providers} for a specific algorithm.
   *
   * @return the builder to continue building.
   */
  B provider();

  /**
   * @param name the name of the {@link Provider}. E.g. "BC" for bouncy castle.
   * @return the builder to continue building.
   */
  B provider(String name);

  /**
   * @param provider the explicit {@link Provider} to use.
   * @return the builder to continue building.
   */
  B provider(Provider provider);

}
