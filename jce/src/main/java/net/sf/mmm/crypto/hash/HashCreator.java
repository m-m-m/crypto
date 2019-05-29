package net.sf.mmm.crypto.hash;

import java.io.OutputStream;

import net.sf.mmm.crypto.CryptBinary;
import net.sf.mmm.crypto.CryptoChunker;

/**
 * This is the interface for a creator of hash values. It is similar to {@link java.security.MessageDigest} but allows
 * additional features like hashing in multiple rounds (hashing of hashes) and gives additional abstraction as well as
 * flexibility.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface HashCreator extends CryptoChunker {

  /**
   * @return a new {@link OutputStream} that automatically {@link #update(byte[]) updates} all
   *         {@link OutputStream#write(byte[]) written} data.
   * @see #wrapStream(OutputStream)
   */
  default OutputStream wrapStream() {

    return wrapStream(null);
  }

  /**
   *
   *
   * Creates a new {@link OutputStream} wraps the given {@link OutputStream}. It will automatically
   * {@link #update(byte[]) update} all {@link OutputStream#write(byte[]) written} data. After data has been written,
   * you may call {@link #hash(boolean)} to get the hash of the data. This method will not {@link #reset() reset} this
   * hasher. Therefore any previous {@link #update(byte[]) updated data} will also influence the hash. The typical usage
   * is to call this method once on a fresh instance of {@link HashCreator}, then write data to that stream and
   * finally get the {@link #hash(boolean) hash}.
   *
   * @param out the {@link OutputStream} to wrap.
   * @return a wrapped {@link OutputStream}.
   * @see #wrapStream()
   * @see java.security.DigestOutputStream
   */
  OutputStream wrapStream(OutputStream out);

  @Override
  default byte[] process(byte[] input, int offset, int length, boolean complete) {

    return hash(input, offset, length, complete);
  }

  /**
   * @param input the data to hash.
   * @return the calculated hash of the current data.
   * @param reset - see {@link #hash(boolean)}.
   * @see java.security.MessageDigest#digest(byte[], int, int)
   */
  default byte[] hash(byte[] input, boolean reset) {

    update(input);
    return hash(true);
  }

  /**
   * @param input the data to hash.
   * @param reset - see {@link #hash(boolean)}.
   * @return the calculated {@link Hash} of the given {@code input} data.
   * @see java.security.MessageDigest#digest(byte[], int, int)
   */
  default Hash hash(CryptBinary input, boolean reset) {

    update(input);
    return new Hash(hash(true));
  }

  /**
   * @param input the data to hash.
   * @param offset the index where to start reading data from {@code input}.
   * @param length the number of bytes to read from {@code input}.
   * @return the calculated hash of the current data.
   * @param reset - see {@link #hash(boolean)}.
   * @see java.security.MessageDigest#digest(byte[], int, int)
   */
  default byte[] hash(byte[] input, int offset, int length, boolean reset) {

    update(input, offset, length);
    return hash(true);
  }

  /**
   * This method calculates the current hash in the cheapest way of the underlying implementation. The state of this
   * {@link HashCreator} after the call of this method is therefore unspecified. Use this method only if you do
   * not care about the further state of this {@link HashCreator}. Otherwise use {@link #hash(boolean)} instead.
   *
   * @return the calculated hash of the current data.
   * @see java.security.MessageDigest#digest()
   */
  default byte[] hash() {

    return hash(true);
  }

  /**
   * @see java.security.MessageDigest#digest()
   *
   * @param reset - {@code true} if this {@link HashCreator} shall be {@link #reset() reset} after the hash
   *        calculation, {@code false} otherwise. A design problem of {@link java.security.MessageDigest} is that it
   *        automatically {@link java.security.MessageDigest#reset() resets} itself on
   *        {@link java.security.MessageDigest#digest() hashing} what prevents calculating intermediate hashes but also
   *        continue the hash calculation. This API allows to workaround this limitation.
   * @return the calculated hash of the current data.
   */
  byte[] hash(boolean reset);

}
