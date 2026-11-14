package io.github.mmm.crypto.algorithm;

import java.security.Provider;
import java.security.SecureRandom;

import io.github.mmm.crypto.provider.SecurityProvider;
import io.github.mmm.crypto.random.RandomFactory;
import io.github.mmm.crypto.random.RandomFactoryImpl;

/// Extends [CryptoAlgorithmImpl] with ability to create
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public class CryptoAlgorithmImplWithRandom extends CryptoAlgorithmImpl {

  private final RandomFactory randomFactory;

  /// The constructor.
  ///
  /// @param algorithm the [algorithm][#getAlgorithm()].
  /// @param provider the security [Provider].
  /// @param randomFactory the [RandomFactory] to use.
  public CryptoAlgorithmImplWithRandom(String algorithm, SecurityProvider provider, RandomFactory randomFactory) {

    super(algorithm, provider);
    if (randomFactory == null) {
      this.randomFactory = RandomFactoryImpl.ofStrong();
    } else {
      this.randomFactory = randomFactory;
    }
  }

  /// @return the [RandomFactory].
  protected RandomFactory getRandomFactory() {

    return this.randomFactory;
  }

  /// @return a new [SecureRandom].
  /// @see RandomFactory#newSecureRandom()
  protected SecureRandom createSecureRandom() {

    return this.randomFactory.newSecureRandom();
  }
}
