package net.sf.mmm.security.api;

import java.security.Provider;

import net.sf.mmm.security.api.algorithm.AbstractSecurityAlgorithm;
import net.sf.mmm.security.api.algorithm.SecurityAlgorithm;
import net.sf.mmm.security.api.provider.SecurityProvider;

/**
 * The abstract base implementation of {@link SecurityAlgorithm}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class AbstractSecurityAlgorithmWithProvider extends AbstractSecurityAlgorithm {

  /** The {@link SecurityProvider}. */
  protected final SecurityProvider provider;

  /**
   * The constructor.
   *
   * @param provider the optional security {@link Provider}.
   */
  public AbstractSecurityAlgorithmWithProvider(SecurityProvider provider) {

    super();
    if (provider == null) {
      this.provider = SecurityProvider.DEFAULT;
    } else {
      this.provider = provider;
    }
  }

  /**
   * @return the {@link SecurityProvider}.
   */
  public SecurityProvider getProvider() {

    return this.provider;
  }

}
