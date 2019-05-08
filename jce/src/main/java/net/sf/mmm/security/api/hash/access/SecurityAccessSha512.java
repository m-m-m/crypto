package net.sf.mmm.security.api.hash.access;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmSha2;
import net.sf.mmm.security.api.hash.SecurityHashConfig;
import net.sf.mmm.security.api.provider.SecurityProvider;

/**
 * {@link SecurityAccessHash} for {@link SecurityAlgorithmSha2#ALGORITHM_SHA_512 SHA 512}.
 *
 * @since 1.0.0
 */
public class SecurityAccessSha512 extends SecurityAccessHash {

  /**
   * The constructor.
   *
   * @param provider the {@link SecurityProvider}.
   * @param iterationCount the {@link SecurityHashConfig#getIterationCount() iteration count}.
   */
  public SecurityAccessSha512(SecurityProvider provider, int iterationCount) {

    super(new SecurityHashConfig(SecurityAlgorithmSha2.ALGORITHM_SHA_512, provider, iterationCount));
  }

  /**
   * @return new default instance.
   */
  public static SecurityAccessSha512 of() {

    return of(1);
  }

  /**
   * @return new instance with {@link SecurityHashConfig#getIterationCount() iteration count} of {@code 2}.
   */
  public static SecurityAccessSha512 of2x() {

    return of(2);
  }

  /**
   * @param iterationCount the {@link SecurityHashConfig#getIterationCount() iteration count}.
   * @return new instance with the given {@link SecurityHashConfig#getIterationCount() iteration count}.
   */
  public static SecurityAccessSha512 of(int iterationCount) {

    return new SecurityAccessSha512(null, iterationCount);
  }

}
