package io.github.mmm.crypto.hash.sha2;

import io.github.mmm.crypto.hash.HashConfig;
import io.github.mmm.crypto.provider.SecurityProvider;

/// [HashConfig] for <a href="https://en.wikipedia.org/wiki/SHA-2">SHA-2</a>. It is actually a family of
/// algorithms such as [SHA-256][Sha256] or [SHA-512][Sha512].
///
/// @since 1.0.0
public abstract class Sha2 extends HashConfig {

  /// The constructor.
  ///
  /// @param algorithm the [hash algorithm][java.security.MessageDigest#getAlgorithm()].
  /// @param provider the [SecurityProvider].
  /// @param iterationCount the [iteration count][#getIterationCount()].
  Sha2(String algorithm, SecurityProvider provider, int iterationCount) {

    super(algorithm, provider, iterationCount);
  }

}
