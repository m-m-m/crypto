package io.github.mmm.crypto.random;

import java.security.SecureRandom;

import io.github.mmm.crypto.AbstractCryptoFactory;

/// Interface for a [factory][AbstractCryptoFactory] to [create][#newRandomCreator()] instances of
/// [RandomCreator] for secure random values.
/// An instance of [RandomFactory] therefore represents a configuration with specific
/// [algorithm][java.security.SecureRandom#getAlgorithm()]. The [Object#toString()] method should give a
/// textual representation of this underlying configuration.
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public interface RandomFactory extends AbstractCryptoFactory, RandomConstants {

  /// @return the new [RandomCreator] instance.
  RandomCreator newRandomCreator();

  /// @return the new unwrapped [SecureRandom].
  SecureRandom newSecureRandom();

}
