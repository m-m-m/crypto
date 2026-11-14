package io.github.mmm.crypto.asymmetric.crypt;

import java.security.PrivateKey;
import java.security.PublicKey;

import io.github.mmm.crypto.crypt.CryptorFactory;
import io.github.mmm.crypto.crypt.Decryptor;
import io.github.mmm.crypto.crypt.Encryptor;

/// Extends [CryptorFactory] for [asymmetric][io.github.mmm.crypto.asymmetric.key.AsymmetricKeyPair] encryption and decryption.
///
/// @param <PR> type of [PrivateKey].
/// @param <PU> type of [PublicKey].
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public interface AsymmetricCryptorFactory<PR extends PrivateKey, PU extends PublicKey> extends CryptorFactory {

  /// @param publicKey the [PublicKey] to use for encryption.
  /// @return the [Encryptor] for encryption.
  default Encryptor newEncryptor(PU publicKey) {

    return newEncryptorUnsafe(publicKey);
  }

  /// @param privateKey the [PrivateKey] to use for decryption.
  /// @return the [Decryptor] for decryption.
  default Decryptor newDecryptor(PR privateKey) {

    return newDecryptorUnsafe(privateKey);
  }

}
