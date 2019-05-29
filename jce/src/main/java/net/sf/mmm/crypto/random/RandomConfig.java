package net.sf.mmm.crypto.random;

import java.security.SecureRandom;

import net.sf.mmm.crypto.algorithm.CryptoAlgorithmConfig;
import net.sf.mmm.crypto.provider.SecurityProvider;

/**
 * {@link CryptoAlgorithmConfig} for {@link RandomFactory#newSecureRandom() secure random}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class RandomConfig extends CryptoAlgorithmConfig {

  private final int reseedCount;

  /**
   * The constructor.
   *
   * @param algorithm the {@link java.security.MessageDigest#getAlgorithm() hash algorithm}.
   */
  public RandomConfig(String algorithm) {

    this(algorithm, Integer.MAX_VALUE);
  }

  /**
   * The constructor.
   *
   * @param algorithm the {@link java.security.MessageDigest#getAlgorithm() hash algorithm}.
   * @param reseedCount the {@link #getReseedCount() re-seed count}.
   */
  public RandomConfig(String algorithm, int reseedCount) {

    this(algorithm, reseedCount, null);
  }

  /**
   * The constructor.
   *
   * @param algorithm the {@link java.security.MessageDigest#getAlgorithm() hash algorithm}.
   * @param provider the {@link SecurityProvider}.
   */
  public RandomConfig(String algorithm, SecurityProvider provider) {

    this(algorithm, Integer.MAX_VALUE, provider);
  }

  /**
   * The constructor.
   *
   * @param algorithm the {@link java.security.MessageDigest#getAlgorithm() hash algorithm}.
   * @param reseedCount the {@link #getReseedCount() re-seed count}.
   * @param provider the {@link SecurityProvider}.
   */
  public RandomConfig(String algorithm, int reseedCount, SecurityProvider provider) {

    super(algorithm, provider);
    if (reseedCount <= 0) {
      throw new IllegalArgumentException("reseedCount:" + reseedCount);
    }
    this.reseedCount = reseedCount;
  }

  /**
   * @return the number of calls to {@link RandomCreator#nextRandom(int)} after which the underlying
   *         {@link SecureRandom} is re-seeded (a smaller random number of random seeds are skipped to reduce
   *         predictability even stronger).
   */
  public int getReseedCount() {

    return this.reseedCount;
  }

}
