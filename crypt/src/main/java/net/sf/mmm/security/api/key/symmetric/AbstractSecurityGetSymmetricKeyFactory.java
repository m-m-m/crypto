package net.sf.mmm.security.api.key.symmetric;

/**
 * Abstract interface to {@link #getSymmetricKeyFactory() get} the {@link SecuritySymmetricKeyFactory}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract interface AbstractSecurityGetSymmetricKeyFactory {

  /**
   * @return the {@link SecuritySymmetricKeyFactory}.
   */
  SecuritySymmetricKeyFactory getSymmetricKeyFactory();

  /**
   * @throws IllegalStateException if {@link #getSymmetricKeyFactory()} is {@code null}.
   * @return the {@link SecuritySymmetricKeyFactory}. Never {@code null}.
   */
  default SecuritySymmetricKeyFactory getSymmetricKeyFactoryRequired() {

    SecuritySymmetricKeyFactory factory = getSymmetricKeyFactory();
    if (factory == null) {
      throw new IllegalStateException("SymmetricKeyFactory is not available!");
    }
    return factory;
  }
}
