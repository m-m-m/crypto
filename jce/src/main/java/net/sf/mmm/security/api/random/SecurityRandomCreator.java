package net.sf.mmm.security.api.random;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithm;

/**
 * The interface for a creator of secure {@link #nextRandom(int) random data}. It is similar to
 * {@link java.security.SecureRandom} but gives additional abstraction.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityRandomCreator extends SecurityAlgorithm, SecurityRandomConstants {

  /**
   * @param bytes the requested number of random bytes.
   * @return the {@code byte} array with the given number of random bytes.
   * @see java.security.SecureRandom#nextBytes(byte[])
   */
  byte[] nextRandom(int bytes);

}
