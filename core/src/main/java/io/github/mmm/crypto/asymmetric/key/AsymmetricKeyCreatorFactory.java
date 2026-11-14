package io.github.mmm.crypto.asymmetric.key;

import io.github.mmm.crypto.AbstractCryptoFactory;
import io.github.mmm.crypto.key.KeyCreator;
import io.github.mmm.crypto.key.KeyCreatorFactory;

/// Interface for a [factory][AbstractCryptoFactory] to [create][#newKeyCreator()] instances of
/// [KeyCreator] for asymmetric cryptographic keys.
/// An instance of [AsymmetricKeyCreatorFactory] therefore represents a configuration with specific
/// [java.security.Key] [algorithm][java.security.Key#getAlgorithm()] and [format][java.security.Key#getFormat()](s).
///
/// @param <K> type of [AsymmetricKeyCreator].
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public interface AsymmetricKeyCreatorFactory<K extends AsymmetricKeyCreator<?, ?, ?>> extends KeyCreatorFactory {

  @Override
  K newKeyCreator();

}
