package io.github.mmm.crypto.algorithm;

import io.github.mmm.crypto.provider.SecurityProvider;

/**
 * Implementation of {@link io.github.mmm.crypto.algorithm.CryptoAlgorithm}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class CryptoAlgorithmImpl extends AbstractCryptoAlgorithmWithProvider {

  private final String algorithm;

  /**
   * The constructor.
   *
   * @param algorithm the {@link #getAlgorithm() algorithm}.
   * @param provider the {@link SecurityProvider}.
   */
  public CryptoAlgorithmImpl(String algorithm, SecurityProvider provider) {

    super(provider);
    this.algorithm = algorithm;
  }

  @Override
  public String getAlgorithm() {

    return this.algorithm;
  }

}
