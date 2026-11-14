package io.github.mmm.crypto.hash.sha2;

import io.github.mmm.crypto.hash.HashConfig;
import io.github.mmm.crypto.provider.SecurityProvider;

/// [HashConfig] for <a href="https://en.wikipedia.org/wiki/SHA-2">SHA-384</a>.
///
/// @since 1.0.0
public class Sha384 extends Sha2 {

  /// [Sha384] using default provider.
  public static final Sha384 SHA_384 = new Sha384(1);

  /// [Sha384] hashing twice using default provider.
  public static final Sha384 SHA_384_X2 = new Sha384(2);

  /// The [algorithm][#getAlgorithm()] name {@value}.
  public static final String ALGORITHM_SHA_384 = "SHA-384";

  /// The constructor.
  ///
  /// @param iterationCount the [iteration count][#getIterationCount()].
  public Sha384(int iterationCount) {

    this(null, iterationCount);
  }

  /// The constructor.
  ///
  /// @param provider the [SecurityProvider] to use.
  public Sha384(SecurityProvider provider) {

    this(provider, 1);
  }

  /// The constructor.
  ///
  /// @param provider the [SecurityProvider] to use.
  /// @param iterationCount the [iteration count][#getIterationCount()].
  public Sha384(SecurityProvider provider, int iterationCount) {

    super(ALGORITHM_SHA_384, provider, iterationCount);
  }

}
