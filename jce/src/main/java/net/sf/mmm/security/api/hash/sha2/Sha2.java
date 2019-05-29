package net.sf.mmm.security.api.hash.sha2;

import net.sf.mmm.security.api.hash.SecurityHashConfig;
import net.sf.mmm.security.api.provider.SecurityProvider;

/**
 * {@link SecurityHashConfig} for <a href="https://en.wikipedia.org/wiki/SHA-2">SHA-2</a>. It is actually a family of
 * algorithms such as {@link Sha256 SHA-256} or {@link Sha512 SHA-512}.
 *
 * @since 1.0.0
 */
public abstract class Sha2 extends SecurityHashConfig {

  /**
   * The constructor.
   *
   * @param algorithm the {@link java.security.MessageDigest#getAlgorithm() hash algorithm}.
   * @param provider the {@link SecurityProvider}.
   * @param iterationCount the {@link #getIterationCount() iteration count}.
   */
  Sha2(String algorithm, SecurityProvider provider, int iterationCount) {

    super(algorithm, provider, iterationCount);
  }

}
