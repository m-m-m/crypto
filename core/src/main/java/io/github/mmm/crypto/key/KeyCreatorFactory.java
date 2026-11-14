package io.github.mmm.crypto.key;

import io.github.mmm.crypto.AbstractCryptoFactory;

/// Interface for a [factory][AbstractCryptoFactory] to [create][#newKeyCreator()] instances of
/// [KeyCreator] for asymmetric cryptographic keys.
/// An instance of [KeyCreatorFactory] therefore represents a configuration with specific [java.security.Key]
/// [algorithm][java.security.Key#getAlgorithm()] and [format][java.security.Key#getFormat()](s).
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public interface KeyCreatorFactory {

  /// @return a new instance of [KeyCreator]. May be reused but is not guaranteed to be thread-safe.
  KeyCreator newKeyCreator();

}
