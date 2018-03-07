package net.sf.mmm.security.impl;

import java.security.Provider;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithm;

/**
 * The abstract base implementation of {@link SecurityAlgorithm}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class AbstractSecurityAlgorithmWithProvider extends AbstractSecurityAlgorithm {

  private final Provider provider;

  /**
   * The constructor.
   *
   * @param provider the optional security {@link Provider}.
   */
  public AbstractSecurityAlgorithmWithProvider(Provider provider) {
    super();
    this.provider = provider;
  }

  /**
   * @return the security {@link Provider}.
   */
  public Provider getProvider() {

    return this.provider;
  }

}
