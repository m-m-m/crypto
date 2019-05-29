package net.sf.mmm.crypto.hash.md5;

import net.sf.mmm.crypto.hash.HashConfig;
import net.sf.mmm.crypto.provider.SecurityProvider;

/**
 * {@link HashConfig} for {@code MD5}. <br>
 * <b>ATTENTION:</b><br>
 * Please note that MD5 is a weak hash algorithm that shall not be used for secure hashing (e.g. for signing).
 *
 * @since 1.0.0
 */
public class Md5 extends HashConfig {

  /** The {@link #getAlgorithm() algorithm} name {@value}. */
  public static final String ALGORITHM_MD5 = "MD5";

  /** {@link Md5} using default provider. */
  public static final Md5 MD5 = new Md5(null, 1);

  /**
   * The constructor.
   *
   * @param provider the {@link SecurityProvider}.
   * @param iterationCount the {@link HashConfig#getIterationCount() iteration count}.
   */
  public Md5(SecurityProvider provider, int iterationCount) {

    super(ALGORITHM_MD5, provider, iterationCount);
  }

  /**
   * @param iterationCount the {@link HashConfig#getIterationCount() iteration count}.
   * @return new instance with the given {@link HashConfig#getIterationCount() iteration count}.
   */
  public static Md5 of(int iterationCount) {

    return new Md5(null, iterationCount);
  }

}
