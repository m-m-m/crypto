package io.github.mmm.crypto.hash.ripemd;

import io.github.mmm.crypto.hash.HashConfig;
import io.github.mmm.crypto.provider.SecurityProvider;
import io.github.mmm.crypto.provider.bc.BouncyCastle;

/// [HashConfig] for <a href="https://en.wikipedia.org/wiki/RIPEMD">RIPEMD-160</a>. This algorithm is used to
/// generate a bitcoin address.
///
/// @since 1.0.0
public class RipeMd160 extends RipeMd {

  /// The [algorithm][#getAlgorithm()] name {@value}.
  public static final String ALGORITHM_RIPEMD_160 = "RIPEMD160";

  /// [RipeMd160] using default provider.
  public static final RipeMd160 RIPEMD_160 = new RipeMd160(1);

  /// The constructor.
  ///
  /// @param iterationCount the [iteration count][#getIterationCount()].
  public RipeMd160(int iterationCount) {

    this(BouncyCastle.getSecurityProvider(), iterationCount);
  }

  /// The constructor.
  ///
  /// @param provider the [SecurityProvider] to use.
  public RipeMd160(SecurityProvider provider) {

    this(provider, 1);
  }

  /// The constructor.
  ///
  /// @param provider the [SecurityProvider] to use.
  /// @param iterationCount the [iteration count][#getIterationCount()].
  public RipeMd160(SecurityProvider provider, int iterationCount) {

    super(ALGORITHM_RIPEMD_160, provider, iterationCount);
  }

}
