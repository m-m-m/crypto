package io.github.mmm.crypto.symmetric.key;

import javax.crypto.SecretKey;

import io.github.mmm.binary.Binary;
import io.github.mmm.crypto.CryptoBinary;
import io.github.mmm.crypto.key.KeyCreator;

/**
 * Extends {@link KeyCreator} for dealing with symmetric cryptographic keys.
 *
 * @see #createKey(String)
 *
 * @param <K> type of {@link SecretKey}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract interface SymmetricKeyCreator<K extends SecretKey> extends KeyCreator {

  /**
   * @param password the secret password.
   * @return the according {@link SecretKey}.
   */
  K createKey(String password);

  /**
   * @param key the {@link SecretKey} as {@link SecretKey#getEncoded() encoded data}.
   * @return the deserialized {@link SecretKey}.
   */
  K createKey(byte[] key);

  /**
   * @param key the {@link SecretKey}.
   * @return the {@link SecretKey}
   */
  byte[] asData(K key);

  /**
   * @param key the {@link SecretKey} to serialize.
   * @return the {@link Binary}.
   */
  default Binary asBinary(K key) {

    return new CryptoBinary(asData(key));
  }

  /**
   * Verify that the given key matches the criteria of this key creator such as {@link #getKeyLength() key length}.
   *
   * @param key the {@link SecretKey} to verify.
   */
  default void verifyKey(K key) {

    int givenKeyLength = getKeyLength(key);
    int expectedKeyLength = getKeyLength();
    if ((givenKeyLength != 0) && (givenKeyLength != expectedKeyLength)) {
      throw new IllegalArgumentException(
          "Secret key has a length of " + givenKeyLength + " bits but expected " + expectedKeyLength + " bits!");
    }
  }

  /**
   * @param key the {@link SecretKey}.
   * @return the {@link #getKeyLength() key length} of the given key.
   */
  int getKeyLength(K key);
}
