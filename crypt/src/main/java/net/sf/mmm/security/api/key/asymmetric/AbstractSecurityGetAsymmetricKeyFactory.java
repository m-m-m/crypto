package net.sf.mmm.security.api.key.asymmetric;

/**
 * Abstract interface to {@link #getAsymmetricKeyFactory() get} the {@link SecurityAsymmetricKeyFactory}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract interface AbstractSecurityGetAsymmetricKeyFactory {

  /**
   * @return the {@link SecurityAsymmetricKeyFactory}.
   */
  SecurityAsymmetricKeyFactory getAsymmetricKeyFactory();

  /**
   * @throws IllegalStateException if {@link #getAsymmetricKeyFactory()} is {@code null}.
   * @return the {@link SecurityAsymmetricKeyFactory}. Never {@code null}.
   */
  default SecurityAsymmetricKeyFactory getAsymmetricKeyFactoryRequired() {

    SecurityAsymmetricKeyFactory factory = getAsymmetricKeyFactory();
    if (factory == null) {
      throw new IllegalStateException("AsymmetricKeyFactory is not available!");
    }
    return factory;
  }
}
