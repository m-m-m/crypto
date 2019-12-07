package io.github.mmm.crypto.random;

/**
 * Abstract interface to {@link #getRandomFactory() get} the {@link RandomFactory}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract interface AbstractSecurityGetRandomFactory {

  /**
   * @return the {@link RandomFactory}. May be {@code null}.
   */
  RandomFactory getRandomFactory();

  /**
   * @throws IllegalStateException if {@link #getRandomFactory()} is {@code null}.
   * @return the {@link RandomFactory}. Never {@code null}.
   */
  default RandomFactory getRandomFactoryRequired() {

    RandomFactory factory = getRandomFactory();
    if (factory == null) {
      throw new IllegalStateException("RandomFactory is not available!");
    }
    return factory;
  }

}
