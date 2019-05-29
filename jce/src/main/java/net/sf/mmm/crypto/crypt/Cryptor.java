package net.sf.mmm.crypto.crypt;

import net.sf.mmm.binary.api.Binary;
import net.sf.mmm.crypto.CryptBinary;
import net.sf.mmm.crypto.CryptoProcessor;

/**
 * The abstract interface for an encryption or decryption function of an cryptographic algorithm. It supports both
 * {@link net.sf.mmm.crypto.symmetric.key.SecuritySymmetricKeyCreator symmetric} as well as
 * {@link net.sf.mmm.crypto.asymmetric.key.AsymmetricKeyPair asymmetric} encryption. Implementations are
 * typically just wrappers of {@link javax.crypto.Cipher}. However this API is much more flexible, safe, and avoids many
 * pitfalls. E.g. multiple {@link javax.crypto.Cipher}s can be combined without the need to change the code using the
 * {@link Cryptor}.
 *
 * @see Decryptor
 * @see Encryptor
 * @see CryptorFactory
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract interface Cryptor extends CryptoProcessor, AbstractGetNonceSize {

  /**
   * @see javax.crypto.Cipher#doFinal()
   *
   * @return the encrypted (or decrypted) data. May be empty or {@code null}.
   */
  default byte[] doFinal() {

    return crypt(Binary.EMPTY_BYTE_ARRAY, true);
  }

  /**
   * @see javax.crypto.Cipher#update(byte[])
   * @see javax.crypto.Cipher#doFinal(byte[])
   *
   * @param input the next chunk of data to encrypt or decrypt.
   * @param complete - {@code true} to complete the encryption or decryption in case this is the last chunk of data,
   *        {@code false} otherwise.
   * @return the encrypted or decrypted data.
   */
  default byte[] crypt(byte[] input, boolean complete) {

    return crypt(input, 0, input.length, complete);
  }

  /**
   * @see javax.crypto.Cipher#update(byte[])
   * @see javax.crypto.Cipher#doFinal(byte[])
   *
   * @param input the next chunk of data to encrypt or decrypt.
   * @param complete - {@code true} to complete the encryption or decryption in case this is the last chunk of data,
   *        {@code false} otherwise.
   * @return the encrypted or decrypted data.
   */
  default byte[] crypt(CryptBinary input, boolean complete) {

    return process(input, complete);
  }

  /**
   * @see javax.crypto.Cipher#update(byte[], int, int)
   * @see javax.crypto.Cipher#doFinal(byte[], int, int)
   *
   * @param input the next chunk of data to encrypt or decrypt.
   * @param offset the offset where to start in the {@code input} array.
   * @param length the number of bytes to read from the {@code input} array.
   * @param output the array where to write the encrypted or decrypted data to.
   * @param outputOffset the offset where to start in the {@code output} array.
   * @param complete - {@code true} to complete the encryption or decryption in case this is the last chunk of data,
   *        {@code false} otherwise.
   * @return the number of bytes that have been written into the {@code output} array.
   */
  byte[] crypt(byte[] input, int offset, int length, boolean complete);

  @Override
  default byte[] process(byte[] input, int offset, int length, boolean complete) {

    return crypt(input, offset, length, complete);
  }

}
