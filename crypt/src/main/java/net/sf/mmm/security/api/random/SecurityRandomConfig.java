package net.sf.mmm.security.api.random;

import java.security.SecureRandom;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmConfig;

/**
 * {@link SecurityAlgorithmConfig} for {@link SecurityRandomFactory#newSecureRandom() secure random}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityRandomConfig extends SecurityAlgorithmConfig {

  private final int reseedCount;

  /**
   * The constructor.
   *
   * @param algorithm the {@link java.security.MessageDigest#getAlgorithm() hash algorithm}.
   */
  public SecurityRandomConfig(String algorithm) {
    this(algorithm, Integer.MAX_VALUE);
  }

  /**
   * The constructor.
   *
   * @param algorithm the {@link java.security.MessageDigest#getAlgorithm() hash algorithm}.
   * @param reseedCount the {@link #getReseedCount() re-seed count}.
   */
  public SecurityRandomConfig(String algorithm, int reseedCount) {
    super(algorithm);
    if (reseedCount <= 0) {
      throw new IllegalArgumentException("reseedCount:" + reseedCount);
    }
    this.reseedCount = reseedCount;
  }

  /**
   * @return the number of calls to {@link SecurityRandomCreator#nextRandom(int)} after which the underlying
   *         {@link SecureRandom} is re-seeded (a smaller random number of random seeds are skipped to reduce
   *         predictability even stronger).
   */
  public int getReseedCount() {

    return this.reseedCount;
  }

}
