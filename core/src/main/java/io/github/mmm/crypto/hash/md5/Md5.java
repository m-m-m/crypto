package io.github.mmm.crypto.hash.md5;

import io.github.mmm.crypto.hash.HashConfig;
import io.github.mmm.crypto.provider.SecurityProvider;

/// [HashConfig] for `MD5`.
/// **ATTENTION:**
/// Please note that MD5 is a weak hash algorithm that shall not be used for secure hashing (e.g. for signing).
///
/// @since 1.0.0
public class Md5 extends HashConfig {

  /// The [algorithm][#getAlgorithm()] name {@value}.
  public static final String ALGORITHM_MD5 = "MD5";

  /// [Md5] using default provider.
  public static final Md5 MD5 = new Md5(null, 1);

  /// The constructor.
  ///
  /// @param provider the [SecurityProvider].
  /// @param iterationCount the [iteration count][HashConfig#getIterationCount()].
  public Md5(SecurityProvider provider, int iterationCount) {

    super(ALGORITHM_MD5, provider, iterationCount);
  }

  /// @param iterationCount the [iteration count][HashConfig#getIterationCount()].
  /// @return new instance with the given [iteration count][HashConfig#getIterationCount()].
  public static Md5 of(int iterationCount) {

    return new Md5(null, iterationCount);
  }

}
