package net.sf.mmm.crypto;

import net.sf.mmm.crypto.asymmetric.sign.SignatureProcessor;

/**
 * This is the interface for a security algorithm function that {@link #update(byte[]) combines chunks of data} to a
 * compact result.
 *
 * @see net.sf.mmm.crypto.hash.HashCreator
 * @see SignatureProcessor
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface CryptoChunker extends CryptoProcessor {

  /**
   * @see java.security.MessageDigest#update(byte[])
   * @see java.security.Signature#update(byte[])
   *
   * @param input the next chunk of data.
   */
  default void update(byte[] input) {

    update(input, 0, input.length);
  }

  /**
   * @see java.security.MessageDigest#update(byte[], int, int)
   * @see java.security.Signature#update(byte[], int, int)
   *
   * @param input the next chunk of data.
   * @param offset the index where to start reading data from {@code input}.
   * @param length the number of bytes to read from {@code input}.
   */
  void update(byte[] input, int offset, int length);

  /**
   * @see java.security.MessageDigest#update(byte[])
   * @see java.security.Signature#update(byte[])
   *
   * @param input the {@link CryptBinary} containing the next chunk of {@link CryptBinary#getData() data}.
   */
  default void update(CryptBinary input) {

    update(input.getRawData());
  }

}
