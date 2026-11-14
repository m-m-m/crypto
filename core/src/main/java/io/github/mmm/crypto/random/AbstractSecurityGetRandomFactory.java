package io.github.mmm.crypto.random;

/// Abstract interface to [get][#getRandomFactory()] the [RandomFactory].
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public abstract interface AbstractSecurityGetRandomFactory {

  /// @return the [RandomFactory]. May be `null`.
  RandomFactory getRandomFactory();

  /// @throws IllegalStateException if [#getRandomFactory()] is `null`.
  /// @return the [RandomFactory]. Never `null`.
  default RandomFactory getRandomFactoryRequired() {

    RandomFactory factory = getRandomFactory();
    if (factory == null) {
      throw new IllegalStateException("RandomFactory is not available!");
    }
    return factory;
  }

}
