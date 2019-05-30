package net.sf.mmm.crypto;

import net.sf.mmm.crypto.algorithm.CryptoAlgorithm;

/**
 * The abstract interface for any object that is based on a security {@link #getAlgorithm() algorithm}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract interface CryptoProcessor extends CryptoAlgorithm {

  /**
   * Generic method to process and transform data.
   * <table summary="method usage examples" border="1">
   * <tr>
   * <th>{@link CryptoProcessor}</th>
   * <th>Equivalent of {@link #process(byte[]) process}(input)</th>
   * </tr>
   * <tr>
   * <td>{@link net.sf.mmm.crypto.hash.HashCreator}</td>
   * <td><code>{@link net.sf.mmm.crypto.hash.HashCreator#update(byte[]) update}(input);
   * return {@link net.sf.mmm.crypto.hash.HashCreator#hash(boolean) hash}(true);</code></td>
   * </tr>
   * <tr>
   * <td>{@link net.sf.mmm.crypto.crypt.Cryptor}</td>
   * <td><code>return {@link net.sf.mmm.crypto.crypt.Cryptor#crypt(byte[], boolean) crypt}(input, true);</code></td>
   * </tr>
   * <tr>
   * <td>{@link net.sf.mmm.crypto.asymmetric.sign.SignatureSigner}</td>
   * <td><code>{@link net.sf.mmm.crypto.asymmetric.sign.SignatureSigner#update(byte[]) update}(input);
   * return {@link net.sf.mmm.crypto.asymmetric.sign.SignatureSigner#signAfterUpdateRaw(boolean) signAfterUpdateRaw}(true);</code></td>
   * </tr>
   * <tr>
   * <td>{@link net.sf.mmm.crypto.asymmetric.sign.SignatureVerifier}</td>
   * <td><code>throw new {@link UnsupportedOperationException}();</code></td>
   * </tr>
   * </table>
   *
   * @param input the data to process.
   * @return the transformed {@code input} data.
   */
  default byte[] process(byte[] input) {

    return process(input, 0, input.length);
  }

  /**
   * Generic method to process and transform data.
   * <table summary="method usage examples" border="1">
   * <tr>
   * <th>{@link CryptoProcessor}</th>
   * <th>Equivalent of {@link #process(byte[], int, int) process}(input, offset, length)</th>
   * </tr>
   * <tr>
   * <td>{@link net.sf.mmm.crypto.hash.HashCreator}</td>
   * <td><code>{@link net.sf.mmm.crypto.hash.HashCreator#update(byte[], int, int) update}(input, offset, length);
   * return {@link net.sf.mmm.crypto.hash.HashCreator#hash(boolean)
   * hash}(true);</code></td>
   * </tr>
   * <tr>
   * <td>{@link net.sf.mmm.crypto.crypt.Cryptor}</td>
   * <td><code>return {@link net.sf.mmm.crypto.crypt.Cryptor#crypt(byte[], int, int, boolean) crypt}(input, offset, length, true);</code></td>
   * </tr>
   * <tr>
   * <td>{@link net.sf.mmm.crypto.asymmetric.sign.SignatureSigner}</td>
   * <td><code>{@link net.sf.mmm.crypto.asymmetric.sign.SignatureSigner#update(byte[], int, int) update}(input, offset, length);
   * return {@link net.sf.mmm.crypto.asymmetric.sign.SignatureSigner#signAfterUpdate(boolean) signAfterUpdate}(true);</code></td>
   * </tr>
   * <tr>
   * <td>{@link net.sf.mmm.crypto.asymmetric.sign.SignatureVerifier}</td>
   * <td><code>throw new {@link UnsupportedOperationException}();</code></td>
   * </tr>
   * </table>
   *
   * @param input the data to process.
   * @param offset the index where to start reading data from {@code input}.
   * @param length the number of bytes to read from {@code input}.
   * @return the transformed {@code input} data.
   */
  default byte[] process(byte[] input, int offset, int length) {

    return process(input, offset, length, true);
  }

  /**
   * Generic method to process and transform data.
   * <table summary="method usage examples" border="1">
   * <tr>
   * <th>{@link CryptoProcessor}</th>
   * <th>Equivalent of {@link #process(byte[], int, int, boolean) process}(input, offset, length, complete)</th>
   * </tr>
   * <tr>
   * <td>{@link net.sf.mmm.crypto.hash.HashCreator}</td>
   * <td><code>{@link net.sf.mmm.crypto.hash.HashCreator#update(byte[], int, int) update}(input, offset, length);
   * return {@link net.sf.mmm.crypto.hash.HashCreator#hash(boolean)
   * hash}(complete);</code></td>
   * </tr>
   * <tr>
   * <td>{@link net.sf.mmm.crypto.crypt.Cryptor}</td>
   * <td><code>return {@link net.sf.mmm.crypto.crypt.Cryptor#crypt(byte[], int, int, boolean) crypt}(input, offset, length, true);</code></td>
   * </tr>
   * <tr>
   * <td>{@link net.sf.mmm.crypto.asymmetric.sign.SignatureSigner}</td>
   * <td><code>{@link net.sf.mmm.crypto.asymmetric.sign.SignatureSigner#update(byte[], int, int) update}(input, offset, length);
   * return {@link net.sf.mmm.crypto.asymmetric.sign.SignatureSigner#signAfterUpdate(boolean) signAfterUpdate}(complete);</code></td>
   * </tr>
   * <tr>
   * <td>{@link net.sf.mmm.crypto.asymmetric.sign.SignatureVerifier}</td>
   * <td><code>throw new {@link UnsupportedOperationException}();</code></td>
   * </tr>
   * </table>
   *
   * @param input the data to process.
   * @param offset the index where to start reading data from {@code input}.
   * @param length the number of bytes to read from {@code input}.
   * @param complete - {@code true} to complete/reset this processor after processing the given {@code input},
   *        {@code false} otherwise.
   * @return the transformed {@code input} data.
   */
  default byte[] process(byte[] input, int offset, int length, boolean complete) {

    throw new UnsupportedOperationException();
  }

  /**
   * @param input the {@link CryptoBinary} {@link CryptoBinary#getData() containing the data} to process.
   * @param complete - {@code true} to complete/reset this processor after processing the given {@code input},
   *        {@code false} otherwise.
   * @return the transformed {@code input} data.
   * @see #process(byte[])
   */
  default byte[] process(CryptoBinary input, boolean complete) {

    byte[] data = input.getRawData();
    return process(data, 0, data.length, complete);
  }

  /**
   * Will reset the internal state of this object. Please note that complex algorithms especially for
   * {@link net.sf.mmm.crypto.crypt.Cryptor} may <b>not</b> reusable. It is therefore preferable to always create a
   * fresh instance for each cryptographic task.
   *
   * @see java.security.MessageDigest#reset()
   */
  void reset();

}
