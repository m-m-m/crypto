package net.sf.mmm.security.api.algorithm;

import net.sf.mmm.security.api.SecurityConfig;
import net.sf.mmm.security.api.provider.SecurityProvider;

/**
 * Abstract base class for a {@link SecurityAlgorithm#getAlgorithm() security algorithm} together with its according
 * parameters.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class SecurityAlgorithmConfig extends SecurityConfig implements SecurityAlgorithm {

  /** @see #getAlgorithm() */
  protected final String algorithm;

  /**
   * The constructor.
   *
   * @param algorithm the {@link #getAlgorithm() algorithm}.
   * @param provider the {@link #getProvider() provider}.
   */
  public SecurityAlgorithmConfig(String algorithm, SecurityProvider provider) {

    super(provider);
    this.algorithm = algorithm;
  }

  @Override
  public String getAlgorithm() {

    return this.algorithm;
  }

}
