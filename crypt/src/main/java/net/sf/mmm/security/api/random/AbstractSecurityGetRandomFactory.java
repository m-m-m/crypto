package net.sf.mmm.security.api.random;

/**
 * Abstract interface to {@link #getRandomFactory() get} the {@link SecurityRandomFactory}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract interface AbstractSecurityGetRandomFactory {

  /**
   * @return the {@link SecurityRandomFactory}. May be {@code null}.
   */
  SecurityRandomFactory getRandomFactory();

  /**
   * @throws IllegalStateException if {@link #getRandomFactory()} is {@code null}.
   * @return the {@link SecurityRandomFactory}. Never {@code null}.
   */
  default SecurityRandomFactory getRandomFactoryRequired() {

    SecurityRandomFactory factory = getRandomFactory();
    if (factory == null) {
      throw new IllegalStateException("RandomFactory is not available!");
    }
    return factory;
  }

}
