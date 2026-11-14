package io.github.mmm.crypto.hash.ripemd;

import io.github.mmm.crypto.hash.HashConfig;
import io.github.mmm.crypto.provider.SecurityProvider;

/// [HashConfig] for <a href="https://en.wikipedia.org/wiki/RIPEMD">RIPEMD</a>. It is actually a family of
/// algorithms such as [RipeMd160] (famous from bitcoin addresses) or [RipeMd256].
///
/// @since 1.0.0
public abstract class RipeMd extends HashConfig {

  /// The constructor.
  ///
  /// @param algorithm the [hash algorithm][java.security.MessageDigest#getAlgorithm()].
  /// @param provider the [SecurityProvider].
  /// @param iterationCount the [iteration count][#getIterationCount()].
  RipeMd(String algorithm, SecurityProvider provider, int iterationCount) {

    super(algorithm, provider, iterationCount);
  }

}
