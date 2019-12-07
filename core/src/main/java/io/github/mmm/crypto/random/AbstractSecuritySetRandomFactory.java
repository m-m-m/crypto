package io.github.mmm.crypto.random;

/**
 * Extends {@link AbstractSecurityGetRandomFactory} with ability to {@link #setRandomFactory(RandomFactory) set}
 * the {@link RandomFactory}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface AbstractSecuritySetRandomFactory extends AbstractSecurityGetRandomFactory {

  /**
   * @param factory the {@link RandomFactory} to set.
   */
  void setRandomFactory(RandomFactory factory);

}
