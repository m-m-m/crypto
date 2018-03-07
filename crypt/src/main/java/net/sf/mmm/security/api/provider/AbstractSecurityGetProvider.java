package net.sf.mmm.security.api.provider;

import java.security.Provider;

/**
 * Abstract interface to {@link #getProvider() get} the security {@link Provider}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract interface AbstractSecurityGetProvider {

  /**
   * @return the security {@link Provider}.
   */
  Provider getProvider();

  /**
   * @throws IllegalStateException if {@link #getProvider()} is {@code null}.
   * @return the {@link Provider}. Never {@code null}.
   */
  default Provider getProviderRequired() {

    Provider provider = getProvider();
    if (provider == null) {
      throw new IllegalStateException("Provider is not available!");
    }
    return provider;
  }
}
