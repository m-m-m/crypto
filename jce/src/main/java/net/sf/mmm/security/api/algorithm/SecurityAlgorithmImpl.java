package net.sf.mmm.security.api.algorithm;

import net.sf.mmm.security.api.AbstractSecurityAlgorithmWithProvider;
import net.sf.mmm.security.api.provider.SecurityProvider;

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
   * @param provider the {@link SecurityProvider}.
   */
  public SecurityAlgorithmImpl(String algorithm, SecurityProvider provider) {

    super(provider);
    this.algorithm = algorithm;
  }

  @Override
  public String getAlgorithm() {

    return this.algorithm;
  }

}
