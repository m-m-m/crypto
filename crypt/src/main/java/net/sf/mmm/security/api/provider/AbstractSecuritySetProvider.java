package net.sf.mmm.security.api.provider;

import java.security.Provider;

/**
 * Extends {@link AbstractSecurityGetProvider} with ability to {@link #setProvider(Provider) set} the {@link Provider}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract interface AbstractSecuritySetProvider extends AbstractSecurityGetProvider {

  /**
   * @param provider the new {@link Provider} to set.
   */
  void setProvider(Provider provider);

}
