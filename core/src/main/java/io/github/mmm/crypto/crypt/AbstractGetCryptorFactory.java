package io.github.mmm.crypto.crypt;

/// Abstract interface to [get][#getCryptorFactory()] the [CryptorFactory].
///
/// @param <C> the type of the [CryptorFactory].
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public abstract interface AbstractGetCryptorFactory<C extends CryptorFactory> {

  /// @return the [CryptorFactory].
  C getCryptorFactory();

  /// @throws IllegalStateException if [#getCryptorFactory()] is `null`.
  /// @return the [CryptorFactory]. Never `null`.
  default C getCryptorFactoryRequired() {

    C factory = getCryptorFactory();
    if (factory == null) {
      throw new IllegalStateException("CryptorFactory is not available!");
    }
    return factory;
  }

}
