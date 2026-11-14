package io.github.mmm.crypto.hash.access;

import io.github.mmm.crypto.CryptoAccess;
import io.github.mmm.crypto.hash.HashConfig;
import io.github.mmm.crypto.hash.HashCreator;
import io.github.mmm.crypto.hash.HashCreatorImplDigest;
import io.github.mmm.crypto.hash.HashCreatorImplMultipleRounds;
import io.github.mmm.crypto.hash.HashFactory;

/// [CryptoAccess] for [HashFactory].
///
/// @since 1.0.0
public class HashAccess extends CryptoAccess implements HashFactory {

  private final HashConfig config;

  /// The constructor.
  ///
  /// @param config the [HashAccess].
  public HashAccess(HashConfig config) {

    super();
    if (config.getIterationCount() <= 0) {
      throw new IllegalArgumentException("config.iterationCount=" + config.getIterationCount());
    }
    this.config = config;
  }

  @Override
  public HashCreator newHashCreator() {

    int iterationCount = this.config.getIterationCount();
    if (iterationCount <= 1) {
      return new HashCreatorImplDigest(this.config.getAlgorithm(), this.config.getProvider());
    } else {
      return new HashCreatorImplMultipleRounds(this.config.getAlgorithm(), this.config.getProvider(), iterationCount);
    }
  }

  @Override
  public String toString() {

    return this.config.getAlgorithm();
  }

  /// @param config the [HashAccess].
  /// @return the [HashAccess].
  public static HashAccess of(HashConfig config) {

    return new HashAccess(config);
  }

}
