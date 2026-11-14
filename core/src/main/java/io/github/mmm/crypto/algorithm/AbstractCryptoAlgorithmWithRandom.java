package io.github.mmm.crypto.algorithm;

import java.security.SecureRandom;

import io.github.mmm.crypto.provider.SecurityProvider;
import io.github.mmm.crypto.random.RandomFactory;
import io.github.mmm.crypto.random.RandomFactoryImpl;

/// Extends [CryptoAlgorithmImpl] with ability to create
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public abstract class AbstractCryptoAlgorithmWithRandom extends AbstractCryptoAlgorithmWithProvider {

  private final RandomFactory randomFactory;

  /// The constructor.
  ///
  /// @param provider the [SecurityProvider].
  /// @param randomFactory the [RandomFactory] to use.
  public AbstractCryptoAlgorithmWithRandom(SecurityProvider provider, RandomFactory randomFactory) {

    super(provider);
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
