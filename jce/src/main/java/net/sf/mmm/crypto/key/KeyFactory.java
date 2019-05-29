package net.sf.mmm.crypto.key;

import net.sf.mmm.crypto.AbstractCryptoFactory;
import net.sf.mmm.crypto.crypt.CryptorFactory;

/**
 * Interface for a {@link AbstractCryptoFactory factory} to {@link #newKeyCreator() create} instances of
 * {@link KeyCreator} for asymmetric cryptographic keys.<br>
 * An instance of {@link KeyFactory} therefore represents a configuration with specific
 * {@link java.security.Key} {@link java.security.Key#getAlgorithm() algorithm} and {@link java.security.Key#getFormat()
 * format}(s). The {@link CryptorFactory#toString()} method should give a textual representation of this
 * underlying configuration.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface KeyFactory {

  /**
   * @return a new instance of {@link KeyCreator}. May be reused but is not guaranteed to be thread-safe.
   */
  KeyCreator newKeyCreator();

}
