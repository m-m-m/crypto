package io.github.mmm.crypto.hash;

import io.github.mmm.crypto.AbstractGetIterationCount;
import io.github.mmm.crypto.algorithm.CryptoAlgorithmConfig;
import io.github.mmm.crypto.hash.access.HashAccess;
import io.github.mmm.crypto.provider.SecurityProvider;

/// [CryptoAlgorithmConfig] for [hashing][HashCreator#hash(byte[], boolean)].
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public class HashConfig extends CryptoAlgorithmConfig implements AbstractGetIterationCount, HashFactory {

  /// The dummy hash algorithm NONE for no hashing (e.g. plain signing without prior hashing).
  public static final String ALGORITHM_NONE = "NONE";

  private final int iterationCount;

  /// The constructor.
  ///
  /// @param algorithm the [hash algorithm][java.security.MessageDigest#getAlgorithm()].
  public HashConfig(String algorithm) {

    this(algorithm, null, 1);
  }

  /// The constructor.
  ///
  /// @param algorithm the [hash algorithm][java.security.MessageDigest#getAlgorithm()].
  /// @param iterationCount the [iteration count][#getIterationCount()].
  public HashConfig(String algorithm, int iterationCount) {

    this(algorithm, null, iterationCount);
  }

  /// The constructor.
  ///
  /// @param algorithm the [hash algorithm][java.security.MessageDigest#getAlgorithm()].
  /// @param provider the [SecurityProvider].
  public HashConfig(String algorithm, SecurityProvider provider) {

    this(algorithm, provider, 1);
  }

  /// The constructor.
  ///
  /// @param algorithm the [hash algorithm][java.security.MessageDigest#getAlgorithm()].
  /// @param provider the [SecurityProvider].
  /// @param iterationCount the [iteration count][#getIterationCount()].
  public HashConfig(String algorithm, SecurityProvider provider, int iterationCount) {

    super(algorithm, provider);
    if (iterationCount < 0) {
      throw new IllegalArgumentException("iterationCount:" + iterationCount);
    }
    this.iterationCount = iterationCount;
  }

  @Override
  public int getIterationCount() {

    return this.iterationCount;
  }

  /// @return a [HashConfig] with the same [algorithm][#getAlgorithm()] but an [iteration count][#getIterationCount()] decreased by 1. If the [iteration count][#getIterationCount()] is already `1`
  ///         then `null` is returned.
  public HashConfig decrementIterationCount() {

    if (this.iterationCount <= 0) {
      return null;
    }
    return new HashConfig(getAlgorithm(), this.provider, this.iterationCount - 1);
  }

  /// @return a new [HashAccess] for this configuration.
  public HashAccess newAccess() {

    return new HashAccess(this);
  }

  @Override
  public HashCreator newHashCreator() {

    return newAccess().newHashCreator();
  }

}
