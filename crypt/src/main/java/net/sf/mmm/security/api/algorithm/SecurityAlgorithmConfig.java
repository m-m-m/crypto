package net.sf.mmm.security.api.algorithm;

import net.sf.mmm.security.impl.AbstractSecurityAlgorithm;

/**
 * Abstract base class for a {@link SecurityAlgorithm#getAlgorithm() security algorithm} together with its according
 * parameters.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class SecurityAlgorithmConfig extends AbstractSecurityAlgorithm {

  private final String algorithm;

  /**
   * The constructor.
   *
   * @param algorithm the {@link #getAlgorithm() algorithm}.
   */
  public SecurityAlgorithmConfig(String algorithm) {

    super();
    this.algorithm = algorithm;
  }

  @Override
  public String getAlgorithm() {

    return this.algorithm;
  }

}
