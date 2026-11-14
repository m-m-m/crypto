package io.github.mmm.crypto.asymmetric.key;

import java.security.PrivateKey;
import java.security.PublicKey;

import io.github.mmm.binary.Binary;
import io.github.mmm.crypto.CryptoBinary;

/// Interface for factory to create instances of [AsymmetricKeyPair], [PrivateKey], and [PublicKey]. It
/// shall only be used internally (as SPI). End-users shall use [AsymmetricKeyCreator].
///
/// @param <PR> type of [PrivateKey].
/// @param <PU> type of [PublicKey].
/// @param <PAIR> type of [AsymmetricKeyPair].
/// @since 1.0.0
public interface AsymmetricKeyPairFactory<PR extends PrivateKey, PU extends PublicKey, PAIR extends AsymmetricKeyPair<PR, PU>>
    extends PrivateKeyFactory<PR>, PublicKeyFactory<PU>, AsymmetricKeyPairFactorySimple<PR, PU, PAIR> {

  /// @param keyPair the [AsymmetricKeyPair] to serialize.
  /// @return the serialized [Binary].
  default Binary asBinary(PAIR keyPair) {

    return new CryptoBinary(asData(keyPair));
  }

  /// @param keyPair the [AsymmetricKeyPair] to serialize.
  /// @return the serialized binary data.
  byte[] asData(PAIR keyPair);

  /// @param data the [AsymmetricKeyPair] in its binary form.
  /// @return the deserialized [AsymmetricKeyPair].
  PAIR createKeyPair(byte[] data);

}
