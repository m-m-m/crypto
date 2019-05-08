package net.sf.mmm.security.api.random;

import java.security.SecureRandom;

import net.sf.mmm.security.api.AbstractSecurityFactory;

/**
 * Interface for a {@link AbstractSecurityFactory factory} to {@link #newRandomCreator() create} instances of
 * {@link SecurityRandomCreator} for secure random values.<br>
 * An instance of {@link SecurityRandomFactory} therefore represents a configuration with specific
 * {@link java.security.SecureRandom#getAlgorithm() algorithm}. The {@link SecurityRandomFactory#toString()} method
 * should give a textual representation of this underlying configuration.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityRandomFactory extends AbstractSecurityFactory, SecurityRandomConstants {

  /**
   * @return the new {@link SecurityRandomCreator} instance.
   */
  SecurityRandomCreator newRandomCreator();

  /**
   * @return the new unwrapped {@link SecureRandom}.
   */
  SecureRandom newSecureRandom();

}
