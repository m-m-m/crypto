package net.sf.mmm.crypto.random;

import java.security.SecureRandom;

import net.sf.mmm.crypto.AbstractCryptoFactory;

/**
 * Interface for a {@link AbstractCryptoFactory factory} to {@link #newRandomCreator() create} instances of
 * {@link RandomCreator} for secure random values.<br>
 * An instance of {@link RandomFactory} therefore represents a configuration with specific
 * {@link java.security.SecureRandom#getAlgorithm() algorithm}. The {@link #toString()} method should give a textual
 * representation of this underlying configuration.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface RandomFactory extends AbstractCryptoFactory, RandomConstants {

  /**
   * @return the new {@link RandomCreator} instance.
   */
  RandomCreator newRandomCreator();

  /**
   * @return the new unwrapped {@link SecureRandom}.
   */
  SecureRandom newSecureRandom();

}
