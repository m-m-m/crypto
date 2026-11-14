package io.github.mmm.crypto.crypt;

import java.io.OutputStream;

/// Interface to [get][#getNonceSize()] the nonce size.
///
/// @since 1.0.0
public interface AbstractGetNonceSize {

  /// Unlike [javax.crypto.Cipher] this API is designed for ease of use. Some cryptographic algorithms require an
  /// [initialization vector][javax.crypto.Cipher#getIV()] (IV) and others do not. With this API you do not have to care
  /// and cannot do things wrong. The nonce will be prepended automatically to the encrypted payload and reconstructed
  /// from there on decryption. This works both for [crypt][Cryptor#crypt(byte\[\], boolean)] and for
  /// [streaming][Encryptor#wrapStream(OutputStream)].
  ///
  /// @return the size of the nonce in bytes or `0` for none.
  /// @see javax.crypto.Cipher#getIV()
  int getNonceSize();

}
