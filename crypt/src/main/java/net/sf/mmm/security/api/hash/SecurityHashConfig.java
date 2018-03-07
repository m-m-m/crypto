package net.sf.mmm.security.api.hash;

import net.sf.mmm.security.api.AbstractSecurityGetIterationCount;
import net.sf.mmm.security.api.algorithm.SecurityAlgorithmConfig;

/**
 * {@link SecurityAlgorithmConfig} for {@link SecurityHashCreator#hash(byte[], boolean) hashing}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityHashConfig extends SecurityAlgorithmConfig
    implements AbstractSecurityGetIterationCount {

  private final int iterationCount;

  /**
   * The constructor.
   *
   * @param algorithm the {@link java.security.MessageDigest#getAlgorithm() hash algorithm}.
   */
  public SecurityHashConfig(String algorithm) {
    this(algorithm, 1);
  }

  /**
   * The constructor.
   *
   * @param algorithm the {@link java.security.MessageDigest#getAlgorithm() hash algorithm}.
   * @param iterationCount the {@link #getIterationCount() iteration count}.
   */
  public SecurityHashConfig(String algorithm, int iterationCount) {
    super(algorithm);
    if (iterationCount <= 0) {
      throw new IllegalArgumentException("iterationCount:" + iterationCount);
    }
    this.iterationCount = iterationCount;
  }

  @Override
  public int getIterationCount() {

    return this.iterationCount;
  }

}
