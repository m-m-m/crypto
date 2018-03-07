package net.sf.mmm.security.api.hash;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmSha2;

/**
 * {@link SecurityHashConfig} for {@link SecurityAlgorithmSha2 SHA-2} variant {@link #ALGORITHM_SHA_256 SHA256}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityHashConfigSha256 extends SecurityHashConfig implements SecurityAlgorithmSha2 {

  /**
   * {@link SecurityAlgorithmSha2 SHA-2} variant {@link #ALGORITHM_SHA_256 SHA256} with a single
   * {@link #getIterationCount() iteration}.
   */
  public static final SecurityHashConfigSha256 SHA_256 = new SecurityHashConfigSha256();

  /**
   * The constructor.
   */
  public SecurityHashConfigSha256() {
    super(ALGORITHM_SHA_256);
  }

  /**
   * The constructor.
   *
   * @param iterationCount the {@link #getIterationCount() iteration count}.
   */
  public SecurityHashConfigSha256(int iterationCount) {
    super(ALGORITHM_SHA_256, iterationCount);
  }

}
