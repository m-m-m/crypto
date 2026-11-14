package io.github.mmm.crypto.crypt;

import java.io.InputStream;

/// Extends [Cryptor] with methods specific for decryption.
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public interface Decryptor extends Cryptor {

  /// @param stream the [InputStream] to wrap.
  /// @return the wrapped [InputStream] that reads from the given [InputStream] after performing decryption.
  InputStream wrapStream(InputStream stream);

  /// @param decryptors the [Decryptor]s to combine with this instance.
  /// @return a [Decryptor] that combines this [Decryptor] with the given
  ///         [Decryptor]s as a chain in that order.
  Decryptor combine(Decryptor... decryptors);

}
