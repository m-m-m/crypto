package io.github.mmm.crypto.key;

import io.github.mmm.crypto.AbstractCryptoFactory;

/**
 * Interface for a {@link AbstractCryptoFactory factory} to {@link #newKeyCreator() create} instances of
 * {@link KeyCreator} for asymmetric cryptographic keys.<br>
 * An instance of {@link KeyCreatorFactory} therefore represents a configuration with specific {@link java.security.Key}
 * {@link java.security.Key#getAlgorithm() algorithm} and {@link java.security.Key#getFormat() format}(s).
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface KeyCreatorFactory {

  /**
   * @return a new instance of {@link KeyCreator}. May be reused but is not guaranteed to be thread-safe.
   */
  KeyCreator newKeyCreator();

}
