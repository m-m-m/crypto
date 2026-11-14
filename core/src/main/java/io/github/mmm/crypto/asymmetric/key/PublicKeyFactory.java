package io.github.mmm.crypto.asymmetric.key;

import java.security.PublicKey;

import io.github.mmm.binary.Binary;
import io.github.mmm.crypto.CryptoBinary;

/// Interface for factory to create instances of [PublicKey].
///
/// @param <PU> type of [PublicKey].
/// @since 1.0.0
public interface PublicKeyFactory<PU extends PublicKey> {

  /// @param publicKey the [PublicKey] to serialize.
  /// @return the serialized [Binary].
  default Binary asBinary(PU publicKey) {

    return new CryptoBinary(asData(publicKey));
  }

  /// @param publicKey the [PublicKey] to serialize.
  /// @return the serialized binary data.
  byte[] asData(PU publicKey);

  /// @param data the [PublicKey] as raw `byte` array.
  /// @return the deserialized [PublicKey].
  PU createPublicKey(byte[] data);

}