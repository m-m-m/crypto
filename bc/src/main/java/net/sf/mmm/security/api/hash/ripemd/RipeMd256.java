package net.sf.mmm.security.api.hash.ripemd;

import net.sf.mmm.security.api.hash.SecurityHashConfig;
import net.sf.mmm.security.api.provider.SecurityProvider;

/**
 * {@link SecurityHashConfig} for <a href="https://en.wikipedia.org/wiki/RIPEMD">RIPEMD-256</a>.
 *
 * @since 1.0.0
 */
public class RipeMd256 extends RipeMd {

  /** The {@link #getAlgorithm() algorithm} name {@value}. */
  public static final String ALGORITHM_RIPEMD_256 = "RIPEMD256";

  /** {@link RipeMd256} using default provider. */
  public static final RipeMd256 RIPEMD_256 = new RipeMd256(1);

  /**
   * The constructor.
   *
   * @param iterationCount the {@link #getIterationCount() iteration count}.
   */
  public RipeMd256(int iterationCount) {

    this(null, iterationCount);
  }

  /**
   * The constructor.
   *
   * @param provider the {@link SecurityProvider} to use.
   */
  public RipeMd256(SecurityProvider provider) {

    this(provider, 1);
  }

  /**
   * The constructor.
   *
   * @param provider the {@link SecurityProvider} to use.
   * @param iterationCount the {@link #getIterationCount() iteration count}.
   */
  public RipeMd256(SecurityProvider provider, int iterationCount) {

    super(ALGORITHM_RIPEMD_256, provider, iterationCount);
  }

}
