package io.github.mmm.crypto.random;

import java.security.SecureRandom;

import io.github.mmm.crypto.algorithm.CryptoAlgorithmConfig;
import io.github.mmm.crypto.provider.SecurityProvider;

/// [CryptoAlgorithmConfig] for [secure random][RandomFactory#newSecureRandom()].
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public class RandomConfig extends CryptoAlgorithmConfig {

  private final int reseedCount;

  /// The constructor.
  ///
  /// @param algorithm the [hash algorithm][java.security.MessageDigest#getAlgorithm()].
  public RandomConfig(String algorithm) {

    this(algorithm, Integer.MAX_VALUE);
  }

  /// The constructor.
  ///
  /// @param algorithm the [hash algorithm][java.security.MessageDigest#getAlgorithm()].
  /// @param reseedCount the [re-seed count][#getReseedCount()].
  public RandomConfig(String algorithm, int reseedCount) {

    this(algorithm, reseedCount, null);
  }

  /// The constructor.
  ///
  /// @param algorithm the [hash algorithm][java.security.MessageDigest#getAlgorithm()].
  /// @param provider the [SecurityProvider].
  public RandomConfig(String algorithm, SecurityProvider provider) {

    this(algorithm, Integer.MAX_VALUE, provider);
  }

  /// The constructor.
  ///
  /// @param algorithm the [hash algorithm][java.security.MessageDigest#getAlgorithm()].
  /// @param reseedCount the [re-seed count][#getReseedCount()].
  /// @param provider the [SecurityProvider].
  public RandomConfig(String algorithm, int reseedCount, SecurityProvider provider) {

    super(algorithm, provider);
    if (reseedCount <= 0) {
      throw new IllegalArgumentException("reseedCount:" + reseedCount);
    }
    this.reseedCount = reseedCount;
  }

  /// @return the number of calls to [RandomCreator#nextRandom(int)] after which the underlying
  ///         [SecureRandom] is re-seeded (a smaller random number of random seeds are skipped to reduce
  ///         predictability even stronger).
  public int getReseedCount() {

    return this.reseedCount;
  }

}
