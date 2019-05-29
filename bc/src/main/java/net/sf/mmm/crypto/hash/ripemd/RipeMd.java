package net.sf.mmm.crypto.hash.ripemd;

import net.sf.mmm.crypto.hash.HashConfig;
import net.sf.mmm.crypto.provider.SecurityProvider;

/**
 * {@link HashConfig} for <a href="https://en.wikipedia.org/wiki/RIPEMD">RIPEMD</a>. It is actually a family of
 * algorithms such as {@link RipeMd160} (famous from bitcoin addresses) or
 * {@link RipeMd256}.
 *
 * @since 1.0.0
 */
public abstract class RipeMd extends HashConfig {

  /**
   * The constructor.
   *
   * @param algorithm the {@link java.security.MessageDigest#getAlgorithm() hash algorithm}.
   * @param provider the {@link SecurityProvider}.
   * @param iterationCount the {@link #getIterationCount() iteration count}.
   */
  RipeMd(String algorithm, SecurityProvider provider, int iterationCount) {

    super(algorithm, provider, iterationCount);
  }

}
