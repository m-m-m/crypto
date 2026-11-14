package io.github.mmm.crypto.crypt;

import java.security.Key;

import io.github.mmm.crypto.AbstractCryptoFactory;

/// Abstract interface for a [factory][AbstractCryptoFactory] to create instances of [Cryptor] for
/// asymmetric cryptography. Please use typesafe methods `newEncryptor` for encryption and `newDecryptor` for
/// decryption from the according sub-interfaces instead of [#newEncryptorUnsafe(Key)] and
/// [#newDecryptorUnsafe(Key)].
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public abstract interface CryptorFactory extends AbstractCryptoFactory {

  /// Please use typesafe `newDecryptor` method instead to avoid mistakes (passing wrong [Key]).
  ///
  /// @param encryptionKey the [Key] to use for encryption.
  /// @return the [Encryptor] for encryption.
  Encryptor newEncryptorUnsafe(Key encryptionKey);

  /// Please use typesafe `newEncryptor` method instead to avoid mistakes (passing wrong [Key]).
  ///
  /// @param decryptionKey the [Key] to use for decryption.
  /// @return the [Decryptor] for decryption.
  Decryptor newDecryptorUnsafe(Key decryptionKey);

}
