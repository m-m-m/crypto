package io.github.mmm.crypto.hash.ripemd;

import io.github.mmm.crypto.hash.HashConfig;
import io.github.mmm.crypto.provider.SecurityProvider;

/// [HashConfig] for <a href="https://en.wikipedia.org/wiki/RIPEMD">RIPEMD-320</a>.
///
/// @since 1.0.0
public class RipeMd320 extends RipeMd {

  /// The [algorithm][#getAlgorithm()] name {@value}.
  public static final String ALGORITHM_RIPEMD_320 = "RIPEMD320";

  /// [RipeMd320] using default provider.
  public static final RipeMd320 RIPEMD_320 = new RipeMd320(1);

  /// The constructor.
  ///
  /// @param iterationCount the [iteration count][#getIterationCount()].
  public RipeMd320(int iterationCount) {

    this(null, iterationCount);
  }

  /// The constructor.
  ///
  /// @param provider the [SecurityProvider] to use.
  public RipeMd320(SecurityProvider provider) {

    this(provider, 1);
  }

  /// The constructor.
  ///
  /// @param provider the [SecurityProvider] to use.
  /// @param iterationCount the [iteration count][#getIterationCount()].
  public RipeMd320(SecurityProvider provider, int iterationCount) {

    super(ALGORITHM_RIPEMD_320, provider, iterationCount);
  }

}
