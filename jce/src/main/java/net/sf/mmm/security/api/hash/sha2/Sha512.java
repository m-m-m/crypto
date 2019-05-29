package net.sf.mmm.security.api.hash.sha2;

import net.sf.mmm.security.api.hash.SecurityHashConfig;
import net.sf.mmm.security.api.provider.SecurityProvider;

/**
 * {@link SecurityHashConfig} for <a href="https://en.wikipedia.org/wiki/SHA-2">SHA-512</a>.
 *
 * @since 1.0.0
 */
public class Sha512 extends Sha2 {

  /** {@link Sha512} using default provider. */
  public static final Sha512 SHA_512 = new Sha512(1);

  /** {@link Sha512} hashing twice using default provider. */
  public static final Sha512 SHA_512_X2 = new Sha512(2);

  /** The {@link #getAlgorithm() algorithm} name {@value}. */
  public static final String ALGORITHM_SHA_512 = "SHA-512";

  /**
   * The constructor.
   *
   * @param iterationCount the {@link #getIterationCount() iteration count}.
   */
  public Sha512(int iterationCount) {

    this(null, iterationCount);
  }

  /**
   * The constructor.
   *
   * @param provider the {@link SecurityProvider} to use.
   */
  public Sha512(SecurityProvider provider) {

    this(provider, 1);
  }

  /**
   * The constructor.
   *
   * @param provider the {@link SecurityProvider} to use.
   * @param iterationCount the {@link #getIterationCount() iteration count}.
   */
  public Sha512(SecurityProvider provider, int iterationCount) {

    super(ALGORITHM_SHA_512, provider, iterationCount);
  }

}
