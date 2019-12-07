package io.github.mmm.crypto.algorithm;

import io.github.mmm.crypto.CryptoConfig;
import io.github.mmm.crypto.provider.SecurityProvider;

/**
 * Abstract base class for a {@link CryptoAlgorithm#getAlgorithm() security algorithm} together with its according
 * parameters.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class CryptoAlgorithmConfig extends CryptoConfig implements CryptoAlgorithm {

  /** @see #getAlgorithm() */
  protected final String algorithm;

  /**
   * The constructor.
   *
   * @param algorithm the {@link #getAlgorithm() algorithm}.
   * @param provider the {@link #getProvider() provider}.
   */
  public CryptoAlgorithmConfig(String algorithm, SecurityProvider provider) {

    super(provider);
    this.algorithm = algorithm;
  }

  @Override
  public String getAlgorithm() {

    return this.algorithm;
  }

}
