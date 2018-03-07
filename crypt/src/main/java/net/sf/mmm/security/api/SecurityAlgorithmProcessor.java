package net.sf.mmm.security.api;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithm;

/**
 * The abstract interface for any object that is based on a security {@link #getAlgorithm() algorithm}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract interface SecurityAlgorithmProcessor extends SecurityAlgorithm {

  /**
   * Generic method to process and transform data.
   * <table border="1">
   * <tr>
   * <th>{@link SecurityAlgorithmProcessor}</th>
   * <th>Equivalent of {@link #process(byte[]) process}(input)</th>
   * </tr>
   * <tr>
   * <td>{@link net.sf.mmm.security.api.hash.SecurityHashCreator}</td>
   * <td><code>{@link net.sf.mmm.security.api.hash.SecurityHashCreator#update(byte[]) update}(input);
   * return {@link net.sf.mmm.security.api.hash.SecurityHashCreator#hash(boolean) hash}(true);</code></td>
   * </tr>
   * <tr>
   * <td>{@link net.sf.mmm.security.api.crypt.SecurityCryptor}</td>
   * <td><code>return {@link net.sf.mmm.security.api.crypt.SecurityCryptor#crypt(byte[], boolean) crypt}(input, true);</code></td>
   * </tr>
   * <tr>
   * <td>{@link net.sf.mmm.security.api.sign.SecuritySignatureSigner}</td>
   * <td><code>{@link net.sf.mmm.security.api.sign.SecuritySignatureSigner#update(byte[]) update}(input);
   * return {@link net.sf.mmm.security.api.sign.SecuritySignatureSigner#sign(boolean) sign}();</code></td>
   * </tr>
   * <tr>
   * <td>{@link net.sf.mmm.security.api.sign.SecuritySignatureVerifier}</td>
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
   * <table border="1">
   * <tr>
   * <th>{@link SecurityAlgorithmProcessor}</th>
   * <th>Equivalent of {@link #process(byte[], int, int) process}(input, offset, length)</th>
   * </tr>
   * <tr>
   * <td>{@link net.sf.mmm.security.api.hash.SecurityHashCreator}</td>
   * <td><code>{@link net.sf.mmm.security.api.hash.SecurityHashCreator#update(byte[], int, int) update}(input, offset, length);
   * return {@link net.sf.mmm.security.api.hash.SecurityHashCreator#hash(boolean)
   * hash}(true);</code></td>
   * </tr>
   * <tr>
   * <td>{@link net.sf.mmm.security.api.crypt.SecurityCryptor}</td>
   * <td><code>return {@link net.sf.mmm.security.api.crypt.SecurityCryptor#crypt(byte[], int, int, boolean) crypt}(input, offset, length, true);</code></td>
   * </tr>
   * <tr>
   * <td>{@link net.sf.mmm.security.api.sign.SecuritySignatureSigner}</td>
   * <td><code>{@link net.sf.mmm.security.api.sign.SecuritySignatureSigner#update(byte[], int, int) update}(input, offset, length);
   * return {@link net.sf.mmm.security.api.sign.SecuritySignatureSigner#sign(boolean) sign}(true);</code></td>
   * </tr>
   * <tr>
   * <td>{@link net.sf.mmm.security.api.sign.SecuritySignatureVerifier}</td>
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

    throw new UnsupportedOperationException();
  }

  /**
   * Will reset the internal state of this object. Please note that complex algorithms especially for
   * {@link net.sf.mmm.security.api.crypt.SecurityCryptor} may <b>not</b> reusable. It is therefore preferable to always
   * create a fresh instance for each cryptographic task.
   *
   * @see java.security.MessageDigest#reset()
   */
  void reset();

}
