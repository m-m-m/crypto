package io.github.mmm.crypto.crypt;

import io.github.mmm.binary.Binary;
import io.github.mmm.crypto.CryptoBinary;
import io.github.mmm.crypto.CryptoProcessor;

/// The abstract interface for an encryption or decryption function of an cryptographic algorithm. It supports both
/// [symmetric][io.github.mmm.crypto.symmetric.key.SymmetricKeyCreator] as well as
/// [asymmetric][io.github.mmm.crypto.asymmetric.key.AsymmetricKeyPair] encryption. Implementations are typically just
/// wrappers of [javax.crypto.Cipher]. However this API is much more flexible, safe, and avoids many pitfalls. E.g.
/// multiple [javax.crypto.Cipher]s can be combined without the need to change the code using the [Cryptor].
///
/// @see Decryptor
/// @see Encryptor
/// @see CryptorFactory
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public abstract interface Cryptor extends CryptoProcessor, AbstractGetNonceSize {

  /// @see javax.crypto.Cipher#doFinal()
  ///
  /// @return the encrypted (or decrypted) data. May be empty or `null`.
  default byte[] doFinal() {

    return crypt(Binary.EMPTY_BYTE_ARRAY, true);
  }

  /// @see javax.crypto.Cipher#update(byte[])
  /// @see javax.crypto.Cipher#doFinal(byte[])
  ///
  /// @param input the next chunk of data to encrypt or decrypt.
  /// @param complete - `true` to complete the encryption or decryption in case this is the last chunk of data,
  ///        `false` otherwise.
  /// @return the encrypted or decrypted data.
  default byte[] crypt(byte[] input, boolean complete) {

    return crypt(input, 0, input.length, complete);
  }

  /// @see javax.crypto.Cipher#update(byte[])
  /// @see javax.crypto.Cipher#doFinal(byte[])
  ///
  /// @param input the next chunk of data to encrypt or decrypt.
  /// @param complete - `true` to complete the encryption or decryption in case this is the last chunk of data,
  ///        `false` otherwise.
  /// @return the encrypted or decrypted data.
  default byte[] crypt(CryptoBinary input, boolean complete) {

    return process(input, complete);
  }

  /// @see javax.crypto.Cipher#update(byte[], int, int)
  /// @see javax.crypto.Cipher#doFinal(byte[], int, int)
  ///
  /// @param input the next chunk of data to encrypt or decrypt.
  /// @param offset the offset where to start in the `input` array.
  /// @param length the number of bytes to read from the `input` array.
  /// @param complete - `true` to complete the encryption or decryption in case this is the last chunk of data,
  ///        `false` otherwise.
  /// @return the number of bytes that have been written into the `output` array.
  byte[] crypt(byte[] input, int offset, int length, boolean complete);

  @Override
  default byte[] process(byte[] input, int offset, int length, boolean complete) {

    return crypt(input, offset, length, complete);
  }

}
