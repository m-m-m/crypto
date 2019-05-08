package net.sf.mmm.security.api.key;

import net.sf.mmm.security.api.AbstractSecurityFactory;
import net.sf.mmm.security.api.crypt.SecurityCryptorFactory;

/**
 * Interface for a {@link AbstractSecurityFactory factory} to {@link #newKeyCreator() create} instances of
 * {@link SecurityKeyCreator} for asymmetric cryptographic keys.<br>
 * An instance of {@link SecurityKeyFactory} therefore represents a configuration with specific
 * {@link java.security.Key} {@link java.security.Key#getAlgorithm() algorithm} and {@link java.security.Key#getFormat()
 * format}(s). The {@link SecurityCryptorFactory#toString()} method should give a textual representation of this
 * underlying configuration.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityKeyFactory {

  /**
   * @return a new instance of {@link SecurityKeyCreator}. May be reused but is not guaranteed to be thread-safe.
   */
  SecurityKeyCreator newKeyCreator();

}
