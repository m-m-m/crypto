package io.github.mmm.crypto.hash;

import io.github.mmm.crypto.AbstractCryptoFactory;

/// Interface for a [factory][AbstractCryptoFactory] to [create][#newHashCreator()] instances of
/// [HashCreator]. An instance of [HashFactory] therefore represents a specific configuration
/// (see [HashConfig]) based on an [hash algorithm][HashConfig#getAlgorithm()].
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public interface HashFactory extends AbstractCryptoFactory {

  /// @return a new instance of [HashCreator] for the configured hash algorithm of this factory.
  HashCreator newHashCreator();

}
