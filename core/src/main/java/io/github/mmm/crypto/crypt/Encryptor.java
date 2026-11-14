package io.github.mmm.crypto.crypt;

import java.io.OutputStream;

/// Extends [Cryptor] with methods specific for encryption.
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public interface Encryptor extends Cryptor {

  /// @param stream the [OutputStream] to wrap.
  /// @return the wrapped [OutputStream] that writes to the given [OutputStream] after performing encryption.
  OutputStream wrapStream(OutputStream stream);

  /// @param encryptors the [Encryptor]s to combine with this instance.
  /// @return a [Encryptor] that combines this [Encryptor] with the given
  ///         [Encryptor]s as a chain in that order.
  Encryptor combine(Encryptor... encryptors);

}
