package io.github.mmm.crypto.hash.sha1;

import io.github.mmm.crypto.hash.HashConfig;
import io.github.mmm.crypto.provider.SecurityProvider;

/// [HashConfig] for `SHA1`.
/// **ATTENTION:**
/// Please note that SHA1 is a weak hash algorithm that shall not be used for secure hashing (e.g. for signing).
///
/// @since 1.0.0
public class Sha1 extends HashConfig {

  /// The [algorithm][#getAlgorithm()] name {@value}.
  public static final String ALGORITHM_SHA1 = "SHA1";

  /// [Sha1] using default provider.
  public static final Sha1 SHA1 = new Sha1(null, 1);

  /// The constructor.
  ///
  /// @param provider the [SecurityProvider].
  /// @param iterationCount the [iteration count][HashConfig#getIterationCount()].
  public Sha1(SecurityProvider provider, int iterationCount) {

    super(ALGORITHM_SHA1, provider, iterationCount);
  }

  /// @param iterationCount the [iteration count][HashConfig#getIterationCount()].
  /// @return new instance with the given [iteration count][HashConfig#getIterationCount()].
  public static Sha1 of(int iterationCount) {

    return new Sha1(null, iterationCount);
  }

}
