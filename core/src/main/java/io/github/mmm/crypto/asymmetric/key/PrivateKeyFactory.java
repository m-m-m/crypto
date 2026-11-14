package io.github.mmm.crypto.asymmetric.key;

import java.security.PrivateKey;

import io.github.mmm.binary.Binary;
import io.github.mmm.crypto.CryptoBinary;

/// Interface for factory to create instances of [PrivateKey].
///
/// @see AsymmetricKeyCreator
///
/// @param <PR> type of [PrivateKey].
/// @since 1.0.0
public interface PrivateKeyFactory<PR extends PrivateKey> {

  /// @param privateKey the [PrivateKey] to serialize.
  /// @return the serialized [Binary].
  default Binary asBinary(PR privateKey) {

    return new CryptoBinary(asData(privateKey));
  }

  /// @param privateKey the [PrivateKey] to serialize.
  /// @return the serialized binary data.
  byte[] asData(PR privateKey);

  /// @param data the [PrivateKey] as raw `byte` array.
  /// @return the deserialized [PrivateKey].
  PR createPrivateKey(byte[] data);

}
