package io.github.mmm.crypto.hash;

import java.io.OutputStream;

import io.github.mmm.crypto.CryptoBinary;
import io.github.mmm.crypto.CryptoChunker;

/// This is the interface for a creator of hash values. It is similar to [java.security.MessageDigest] but allows
/// additional features like hashing in multiple rounds (hashing of hashes) and gives additional abstraction as well as
/// flexibility.
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public interface HashCreator extends CryptoChunker {

  /// @return a new [OutputStream] that automatically [updates][#update(byte[])] all
  ///         [written][OutputStream#write(byte[])] data.
  /// @see #wrapStream(OutputStream)
  default OutputStream wrapStream() {

    return wrapStream(null);
  }

  /// Creates a new [OutputStream] wraps the given [OutputStream]. It will automatically
  /// [update][#update(byte[])] all [written][OutputStream#write(byte[])] data. After data has been written,
  /// you may call [#hash(boolean)] to get the hash of the data. This method will not [reset][#reset()] this
  /// hasher. Therefore any previous [updated data][#update(byte[])] will also influence the hash. The typical usage
  /// is to call this method once on a fresh instance of [HashCreator], then write data to that stream and
  /// finally get the [hash][#hash(boolean)].
  ///
  /// @param out the [OutputStream] to wrap.
  /// @return a wrapped [OutputStream].
  /// @see #wrapStream()
  /// @see java.security.DigestOutputStream
  OutputStream wrapStream(OutputStream out);

  @Override
  default byte[] process(byte[] input, int offset, int length, boolean complete) {

    return hash(input, offset, length, complete);
  }

  /// @param input the data to hash.
  /// @return the calculated hash of the current data.
  /// @param reset - see [#hash(boolean)].
  /// @see java.security.MessageDigest#digest(byte[], int, int)
  default byte[] hash(byte[] input, boolean reset) {

    update(input);
    return hash(true);
  }

  /// @param input the data to hash.
  /// @param reset - see [#hash(boolean)].
  /// @return the calculated [Hash] of the given `input` data.
  /// @see java.security.MessageDigest#digest(byte[], int, int)
  default Hash hash(CryptoBinary input, boolean reset) {

    update(input);
    return new Hash(hash(true));
  }

  /// @param input the data to hash.
  /// @param offset the index where to start reading data from `input`.
  /// @param length the number of bytes to read from `input`.
  /// @return the calculated hash of the current data.
  /// @param reset - see [#hash(boolean)].
  /// @see java.security.MessageDigest#digest(byte[], int, int)
  default byte[] hash(byte[] input, int offset, int length, boolean reset) {

    update(input, offset, length);
    return hash(true);
  }

  /// This method calculates the current hash in the cheapest way of the underlying implementation. The state of this
  /// [HashCreator] after the call of this method is therefore unspecified. Use this method only if you do
  /// not care about the further state of this [HashCreator]. Otherwise use [#hash(boolean)] instead.
  ///
  /// @return the calculated hash of the current data.
  /// @see java.security.MessageDigest#digest()
  default byte[] hash() {

    return hash(true);
  }

  /// @see java.security.MessageDigest#digest()
  ///
  /// @param reset - `true` if this [HashCreator] shall be [reset][#reset()] after the hash
  ///        calculation, `false` otherwise. A design problem of [java.security.MessageDigest] is that it
  ///        automatically [resets][java.security.MessageDigest#reset()] itself on
  ///        [hashing][java.security.MessageDigest#digest()] what prevents calculating intermediate hashes but also
  ///        continue the hash calculation. This API allows to workaround this limitation.
  /// @return the calculated hash of the current data.
  byte[] hash(boolean reset);

}
