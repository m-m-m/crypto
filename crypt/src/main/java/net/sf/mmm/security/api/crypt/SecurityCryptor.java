package net.sf.mmm.security.api.crypt;

import net.sf.mmm.security.api.SecurityAlgorithmProcessor;
import net.sf.mmm.security.api.SecurityBinaryType;
import net.sf.mmm.util.datatype.api.Binary;

/**
 * The abstract interface for an encryption or decryption function of an cryptographic algorithm. It supports both
 * {@link net.sf.mmm.security.api.key.symmetric.SecuritySymmetricKey symmetric} as well as
 * {@link net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyPair asymmetric} encryption. Implementations are
 * typically just wrappers of {@link javax.crypto.Cipher}. However this API gives additional abstraction and
 * flexibility. E.g. multiple {@link javax.crypto.Cipher}s can be combined without the need to change the code using the
 * {@link SecurityCryptor}.
 *
 * @see SecurityDecryptor
 * @see SecurityEncryptor
 * @see SecurityCryptorFactory
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract interface SecurityCryptor
    extends SecurityAlgorithmProcessor, SecurityCryptorConstants, AbstractSecurityGetNonceSize {

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
  default byte[] crypt(SecurityBinaryType input, boolean complete) {

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
