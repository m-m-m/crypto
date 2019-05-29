package net.sf.mmm.crypto.hash.sha1;

import net.sf.mmm.crypto.hash.HashConfig;
import net.sf.mmm.crypto.provider.SecurityProvider;

/**
 * {@link HashConfig} for {@code SHA1}. <br>
 * <b>ATTENTION:</b><br>
 * Please note that SHA1 is a weak hash algorithm that shall not be used for secure hashing (e.g. for signing).
 *
 * @since 1.0.0
 */
public class Sha1 extends HashConfig {

  /** The {@link #getAlgorithm() algorithm} name {@value}. */
  public static final String ALGORITHM_SHA1 = "SHA1";

  /** {@link Sha1} using default provider. */
  public static final Sha1 SHA1 = new Sha1(null, 1);

  /**
   * The constructor.
   *
   * @param provider the {@link SecurityProvider}.
   * @param iterationCount the {@link HashConfig#getIterationCount() iteration count}.
   */
  public Sha1(SecurityProvider provider, int iterationCount) {

    super(ALGORITHM_SHA1, provider, iterationCount);
  }

  /**
   * @param iterationCount the {@link HashConfig#getIterationCount() iteration count}.
   * @return new instance with the given {@link HashConfig#getIterationCount() iteration count}.
   */
  public static Sha1 of(int iterationCount) {

    return new Sha1(null, iterationCount);
  }

}
