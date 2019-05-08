package net.sf.mmm.security.api.crypt;

/**
 * Abstract interface to {@link #getCryptorFactory() get} the {@link SecurityCryptorFactory}.
 *
 * @param <C> the type of the {@link SecurityCryptorFactory}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract interface AbstractSecurityGetCryptorFactory<C extends SecurityCryptorFactory> {

  /**
   * @return the {@link SecurityCryptorFactory}.
   */
  C getCryptorFactory();

  /**
   * @throws IllegalStateException if {@link #getCryptorFactory()} is {@code null}.
   * @return the {@link SecurityCryptorFactory}. Never {@code null}.
   */
  default C getCryptorFactoryRequired() {

    C factory = getCryptorFactory();
    if (factory == null) {
      throw new IllegalStateException("CryptorFactory is not available!");
    }
    return factory;
  }

}
