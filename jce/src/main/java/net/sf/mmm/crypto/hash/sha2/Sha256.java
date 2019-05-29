package net.sf.mmm.crypto.hash.sha2;

import net.sf.mmm.crypto.hash.HashConfig;
import net.sf.mmm.crypto.provider.SecurityProvider;

/**
 * {@link HashConfig} for <a href="https://en.wikipedia.org/wiki/SHA-2">SHA-256</a>.
 *
 * @since 1.0.0
 */
public class Sha256 extends Sha2 {

  /** The {@link #getAlgorithm() algorithm} name {@value}. */
  public static final String ALGORITHM_SHA_256 = "SHA-256";

  /** {@link Sha256} using default provider. */
  public static final Sha256 SHA_256 = new Sha256(1);

  /** {@link Sha256} hashing twice using default provider. */
  public static final Sha256 SHA_256_X2 = new Sha256(2);

  /**
   * The constructor.
   *
   * @param iterationCount the {@link #getIterationCount() iteration count}.
   */
  public Sha256(int iterationCount) {

    this(null, iterationCount);
  }

  /**
   * The constructor.
   *
   * @param provider the {@link SecurityProvider} to use.
   */
  public Sha256(SecurityProvider provider) {

    this(provider, 1);
  }

  /**
   * The constructor.
   *
   * @param provider the {@link SecurityProvider} to use.
   * @param iterationCount the {@link #getIterationCount() iteration count}.
   */
  public Sha256(SecurityProvider provider, int iterationCount) {

    super(ALGORITHM_SHA_256, provider, iterationCount);
  }

}
