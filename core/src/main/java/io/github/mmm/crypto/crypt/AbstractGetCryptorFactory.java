package io.github.mmm.crypto.crypt;

/**
 * Abstract interface to {@link #getCryptorFactory() get} the {@link CryptorFactory}.
 *
 * @param <C> the type of the {@link CryptorFactory}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract interface AbstractGetCryptorFactory<C extends CryptorFactory> {

  /**
   * @return the {@link CryptorFactory}.
   */
  C getCryptorFactory();

  /**
   * @throws IllegalStateException if {@link #getCryptorFactory()} is {@code null}.
   * @return the {@link CryptorFactory}. Never {@code null}.
   */
  default C getCryptorFactoryRequired() {

    C factory = getCryptorFactory();
    if (factory == null) {
      throw new IllegalStateException("CryptorFactory is not available!");
    }
    return factory;
  }

}
