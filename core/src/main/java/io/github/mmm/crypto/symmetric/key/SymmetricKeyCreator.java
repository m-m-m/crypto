package io.github.mmm.crypto.symmetric.key;

import javax.crypto.SecretKey;

import io.github.mmm.binary.Binary;
import io.github.mmm.crypto.CryptoBinary;
import io.github.mmm.crypto.key.KeyCreator;

/// Extends [KeyCreator] for dealing with symmetric cryptographic keys.
///
/// @see #createKey(String)
///
/// @param <K> type of [SecretKey].
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public abstract interface SymmetricKeyCreator<K extends SecretKey> extends KeyCreator {

  /// @param password the secret password.
  /// @return the according [SecretKey].
  K createKey(String password);

  /// @param key the [SecretKey] as [encoded data][SecretKey#getEncoded()].
  /// @return the deserialized [SecretKey].
  K createKey(byte[] key);

  /// @param key the [SecretKey].
  /// @return the [SecretKey]
  byte[] asData(K key);

  /// @param key the [SecretKey] to serialize.
  /// @return the [Binary].
  default Binary asBinary(K key) {

    return new CryptoBinary(asData(key));
  }

  /// Verify that the given key matches the criteria of this key creator such as [key length][#getKeyLength()].
  ///
  /// @param key the [SecretKey] to verify.
  default void verifyKey(K key) {

    int givenKeyLength = getKeyLength(key);
    int expectedKeyLength = getKeyLength();
    if ((givenKeyLength != 0) && (givenKeyLength != expectedKeyLength)) {
      throw new IllegalArgumentException(
          "Secret key has a length of " + givenKeyLength + " bits but expected " + expectedKeyLength + " bits!");
    }
  }

  /// @param key the [SecretKey].
  /// @return the [key length][#getKeyLength()] of the given key.
  int getKeyLength(K key);
}
