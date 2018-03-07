package net.sf.mmm.security.api.hash;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmSha2;

/**
 * {@link SecurityHashConfig} for {@link SecurityAlgorithmSha2 SHA-2} variant {@link #ALGORITHM_SHA_512 SHA512}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityHashConfigSha512 extends SecurityHashConfig implements SecurityAlgorithmSha2 {

  /**
   * {@link SecurityAlgorithmSha2 SHA-2} variant {@link #ALGORITHM_SHA_512 SHA512} with a single
   * {@link #getIterationCount() iteration}.
   */
  public static final SecurityHashConfigSha512 SHA_512 = new SecurityHashConfigSha512();

  /**
   * The constructor.
   */
  public SecurityHashConfigSha512() {
    super(ALGORITHM_SHA_512);
  }

  /**
   * The constructor.
   *
   * @param iterationCount the {@link #getIterationCount() iteration count}.
   */
  public SecurityHashConfigSha512(int iterationCount) {
    super(ALGORITHM_SHA_512, iterationCount);
  }

}
