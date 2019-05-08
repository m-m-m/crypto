package net.sf.mmm.security.api.hash.access;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmSha2;
import net.sf.mmm.security.api.hash.SecurityHashConfig;
import net.sf.mmm.security.api.provider.SecurityProvider;

/**
 * {@link SecurityAccessHash} for {@link SecurityAlgorithmSha2#ALGORITHM_SHA_256 SHA 256}.
 *
 * @since 1.0.0
 */
public class SecurityAccessSha256 extends SecurityAccessHash {

  /**
   * The constructor.
   *
   * @param provider the {@link SecurityProvider}.
   * @param iterationCount the {@link SecurityHashConfig#getIterationCount() iteration count}.
   */
  public SecurityAccessSha256(SecurityProvider provider, int iterationCount) {

    super(new SecurityHashConfig(SecurityAlgorithmSha2.ALGORITHM_SHA_256, provider, iterationCount));
  }

  /**
   * @return new default instance.
   */
  public static SecurityAccessSha256 of() {

    return of(1);
  }

  /**
   * @return new instance with {@link SecurityHashConfig#getIterationCount() iteration count} of {@code 2}.
   */
  public static SecurityAccessSha256 of2x() {

    return of(2);
  }

  /**
   * @param iterationCount the {@link SecurityHashConfig#getIterationCount() iteration count}.
   * @return new instance with the given {@link SecurityHashConfig#getIterationCount() iteration count}.
   */
  public static SecurityAccessSha256 of(int iterationCount) {

    return new SecurityAccessSha256(null, iterationCount);
  }

}
