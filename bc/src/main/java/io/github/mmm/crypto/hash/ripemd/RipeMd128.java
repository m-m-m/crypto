package io.github.mmm.crypto.hash.ripemd;

import io.github.mmm.crypto.hash.HashConfig;
import io.github.mmm.crypto.provider.SecurityProvider;

/**
 * {@link HashConfig} for <a href="https://en.wikipedia.org/wiki/RIPEMD">RIPEMD-128</a>.
 *
 * @since 1.0.0
 */
public class RipeMd128 extends RipeMd {

  /** The {@link #getAlgorithm() algorithm} name {@value}. */
  public static final String ALGORITHM_RIPEMD_128 = "RIPEMD128";

  /** {@link RipeMd128} using default provider. */
  public static final RipeMd128 RIPEMD_256 = new RipeMd128(1);

  /**
   * The constructor.
   *
   * @param iterationCount the {@link #getIterationCount() iteration count}.
   */
  public RipeMd128(int iterationCount) {

    this(null, iterationCount);
  }

  /**
   * The constructor.
   *
   * @param provider the {@link SecurityProvider} to use.
   */
  public RipeMd128(SecurityProvider provider) {

    this(provider, 1);
  }

  /**
   * The constructor.
   *
   * @param provider the {@link SecurityProvider} to use.
   * @param iterationCount the {@link #getIterationCount() iteration count}.
   */
  public RipeMd128(SecurityProvider provider, int iterationCount) {

    super(ALGORITHM_RIPEMD_128, provider, iterationCount);
  }

}
