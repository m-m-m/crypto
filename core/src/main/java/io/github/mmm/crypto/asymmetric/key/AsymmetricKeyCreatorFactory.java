package io.github.mmm.crypto.asymmetric.key;

import io.github.mmm.crypto.AbstractCryptoFactory;
import io.github.mmm.crypto.key.KeyCreator;
import io.github.mmm.crypto.key.KeyCreatorFactory;

/**
 * Interface for a {@link AbstractCryptoFactory factory} to {@link #newKeyCreator() create} instances of
 * {@link KeyCreator} for asymmetric cryptographic keys.<br>
 * An instance of {@link AsymmetricKeyCreatorFactory} therefore represents a configuration with specific
 * {@link java.security.Key} {@link java.security.Key#getAlgorithm() algorithm} and {@link java.security.Key#getFormat()
 * format}(s).
 *
 * @param <K> type of {@link AsymmetricKeyCreator}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface AsymmetricKeyCreatorFactory<K extends AsymmetricKeyCreator<?, ?, ?>> extends KeyCreatorFactory {

  @Override
  K newKeyCreator();

}
