package io.github.mmm.crypto.hash.sha2;

import io.github.mmm.crypto.hash.HashConfig;
import io.github.mmm.crypto.provider.SecurityProvider;

/**
 * {@link HashConfig} for <a href="https://en.wikipedia.org/wiki/SHA-2">SHA-224</a>.
 *
 * @since 1.0.0
 */
public class Sha224 extends Sha2 {

  /** {@link Sha224} using default provider. */
  public static final Sha224 SHA_224 = new Sha224(1);

  /** {@link Sha224} hashing twice using default provider. */
  public static final Sha224 SHA_224_X2 = new Sha224(2);

  /** The {@link #getAlgorithm() algorithm} name {@value}. */
  public static final String ALGORITHM_SHA_224 = "SHA-224";

  /**
   * The constructor.
   *
   * @param iterationCount the {@link #getIterationCount() iteration count}.
   */
  public Sha224(int iterationCount) {

    this(null, iterationCount);
  }

  /**
   * The constructor.
   *
   * @param provider the {@link SecurityProvider} to use.
   */
  public Sha224(SecurityProvider provider) {

    this(provider, 1);
  }

  /**
   * The constructor.
   *
   * @param provider the {@link SecurityProvider} to use.
   * @param iterationCount the {@link #getIterationCount() iteration count}.
   */
  public Sha224(SecurityProvider provider, int iterationCount) {

    super(ALGORITHM_SHA_224, provider, iterationCount);
  }

}
