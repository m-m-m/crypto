package net.sf.mmm.security.api.hash;

/**
 * Abstract interface to {@link #getHashFactory() get} the {@link SecurityHashFactory}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract interface AbstractSecurityGetHashFactory {

  /**
   * @return the {@link SecurityHashFactory}.
   */
  SecurityHashFactory getHashFactory();

  /**
   * @throws IllegalStateException if {@link #getHashFactory()} is {@code null}.
   * @return the {@link SecurityHashFactory}. Never {@code null}.
   */
  default SecurityHashFactory getHashFactoryRequired() {

    SecurityHashFactory factory = getHashFactory();
    if (factory == null) {
      throw new IllegalStateException("HashFactory is not available!");
    }
    return factory;
  }

}
