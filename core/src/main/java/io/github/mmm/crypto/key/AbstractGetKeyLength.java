package io.github.mmm.crypto.key;

/// Interface to [get][#getKeyLength()] the [key-length][#getKeyLength()].
///
/// @since 1.0.0-beta1
public interface AbstractGetKeyLength {

  /// @return the length of the key in bits. The bigger the key length the stronger and more secure the encryption but
  ///         also the more performance is required for computation. Reasonable values depend on the
  ///         [algorithm][io.github.mmm.crypto.algorithm.CryptoAlgorithm#getAlgorithm()]: A recent value for
  ///         RSA is 4096 bits while for PBKDF2 256 is sufficient. However, recommended and secure values change over
  ///         time as computing power is increasing. Therefore you should research the web to find an accurate value.
  int getKeyLength();

}
