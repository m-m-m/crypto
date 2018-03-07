package net.sf.mmm.security.impl;

import java.security.Provider;

/**
 * Implementation of {@link net.sf.mmm.security.api.algorithm.SecurityAlgorithm}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class SecurityAlgorithmImpl extends AbstractSecurityAlgorithmWithProvider {

  private final String algorithm;

  /**
   * The constructor.
   *
   * @param algorithm the {@link #getAlgorithm() algorithm}.
   * @param provider the security {@link Provider}.
   */
  public SecurityAlgorithmImpl(String algorithm, Provider provider) {
    super(provider);
    this.algorithm = algorithm;
  }

  @Override
  public String getAlgorithm() {

    return this.algorithm;
  }

}
