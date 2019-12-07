package io.github.mmm.crypto.crypt;

import java.security.Key;

import io.github.mmm.crypto.AbstractCryptoFactory;

/**
 * Abstract interface for a {@link AbstractCryptoFactory factory} to create instances of {@link Cryptor} for
 * asymmetric cryptography. Please use typesafe methods {@code newEncryptor} for encryption and {@code newDecryptor} for
 * decryption from the according sub-interfaces instead of {@link #newEncryptorUnsafe(Key)} and
 * {@link #newDecryptorUnsafe(Key)}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract interface CryptorFactory extends AbstractCryptoFactory {

  /**
   * Please use typesafe {@code newDecryptor} method instead to avoid mistakes (passing wrong {@link Key}).
   *
   * @param encryptionKey the {@link Key} to use for encryption.
   * @return the {@link Encryptor} for encryption.
   */
  Encryptor newEncryptorUnsafe(Key encryptionKey);

  /**
   * Please use typesafe {@code newEncryptor} method instead to avoid mistakes (passing wrong {@link Key}).
   *
   * @param decryptionKey the {@link Key} to use for decryption.
   * @return the {@link Decryptor} for decryption.
   */
  Decryptor newDecryptorUnsafe(Key decryptionKey);

}
