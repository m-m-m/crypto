package io.github.mmm.crypto.symmetric.key;

import io.github.mmm.crypto.key.KeyCreatorFactory;

/// Interface for a [factory][io.github.mmm.crypto.AbstractCryptoFactory] to [create][#newKeyCreator()] instances of
/// [SymmetricKeyCreator] for symmetric cryptographic keys. An instance of [SymmetricKeyCreatorFactory] therefore
/// represents a configuration with specific [java.security.Key] [algorithm][java.security.Key#getAlgorithm()] and
/// [format][java.security.Key#getFormat()]s.
///
/// @param <C> type of [SymmetricKeyCreator].
/// @since 1.0.0
public interface SymmetricKeyCreatorFactory<C extends SymmetricKeyCreator<?>> extends KeyCreatorFactory {

  @Override
  C newKeyCreator();

}
