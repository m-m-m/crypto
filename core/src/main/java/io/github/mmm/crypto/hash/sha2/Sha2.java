package io.github.mmm.crypto.hash.sha2;

import io.github.mmm.crypto.hash.HashConfig;
import io.github.mmm.crypto.provider.SecurityProvider;

/**
 * {@link HashConfig} for <a href="https://en.wikipedia.org/wiki/SHA-2">SHA-2</a>. It is actually a family of
 * algorithms such as {@link Sha256 SHA-256} or {@link Sha512 SHA-512}.
 *
 * @since 1.0.0
 */
public abstract class Sha2 extends HashConfig {

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
