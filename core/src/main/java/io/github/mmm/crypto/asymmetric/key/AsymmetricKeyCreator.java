package io.github.mmm.crypto.asymmetric.key;

import java.security.PrivateKey;
import java.security.PublicKey;

import io.github.mmm.binary.Binary;
import io.github.mmm.crypto.CryptoBinary;
import io.github.mmm.crypto.CryptoBinaryFormat;
import io.github.mmm.crypto.key.KeyCreator;

/// Extends [KeyCreator] for dealing with asymmetric cryptographic keys.
///
/// @see #generateKeyPair()
/// @see #createPrivateKey(byte[], String)
/// @see #createPublicKey(byte[], String)
/// @see #createKeyPair(byte[], String)
///
/// @param <PR> type of [PrivateKey].
/// @param <PU> type of [PublicKey].
/// @param <PAIR> type of [AsymmetricKeyPair].
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public interface AsymmetricKeyCreator<PR extends PrivateKey, PU extends PublicKey, PAIR extends AsymmetricKeyPair<PR, PU>>
    extends KeyCreator, AsymmetricKeyPairFactory<PR, PU, PAIR> {

  /// @return a new [AsymmetricKeyPair] with a generated [private][AsymmetricKeyPair#getPrivateKey()] and
  ///         [public][AsymmetricKeyPair#getPublicKey()] key for the underlying cryptography.
  PAIR generateKeyPair();

  @Override
  default byte[] asData(PR privateKey) {

    return asData(privateKey, CryptoBinaryFormat.FORMAT_COMPACT);
  }

  /// @param privateKey the [PrivateKey] to serialize.
  /// @param format the the [CryptoBinaryFormat] to use.
  /// @return the [Binary].
  default Binary asBinary(PR privateKey, String format) {

    return new CryptoBinary(asData(privateKey, format));
  }

  /// @param privateKey the [PrivateKey] to serialize.
  /// @param format the the [CryptoBinaryFormat] to use.
  /// @return the binary data.
  byte[] asData(PR privateKey, String format);

  @Override
  default PR createPrivateKey(byte[] data) {

    return createPrivateKey(data, null);
  }

  /// @param data the [PrivateKey] as raw `byte` array.
  /// @param format the [CryptoBinaryFormat] to use.
  /// @return the deserialized [PrivateKey].
  PR createPrivateKey(byte[] data, String format);

  @Override
  default byte[] asData(PU publicKey) {

    return asData(publicKey, CryptoBinaryFormat.FORMAT_COMPACT);
  }

  /// @param publicKey the [PublicKey] to serialize.
  /// @param format the the [CryptoBinaryFormat] to use.
  /// @return the [Binary].
  default Binary asBinary(PU publicKey, String format) {

    return new CryptoBinary(asData(publicKey, format));
  }

  /// @param publicKey the [PublicKey] to serialize.
  /// @param format the the [CryptoBinaryFormat] to use.
  /// @return the binary data.
  byte[] asData(PU publicKey, String format);

  @Override
  default PU createPublicKey(byte[] data) {

    return createPublicKey(data, null);
  }

  /// @param data the [PublicKey] as raw `byte` array.
  /// @param format the the [CryptoBinaryFormat] to use.
  /// @return the deserialized [PublicKey].
  PU createPublicKey(byte[] data, String format);

  @Override
  default byte[] asData(PAIR keyPair) {

    return asData(keyPair, CryptoBinaryFormat.FORMAT_COMPACT);
  }

  /// @param keyPair the [AsymmetricKeyPair] to serialize.
  /// @param format the the [CryptoBinaryFormat] to use.
  /// @return the serialized [Binary].
  default Binary asBinary(PAIR keyPair, String format) {

    return new CryptoBinary(asData(keyPair, format));
  }

  /// @param keyPair the [AsymmetricKeyPair] to serialize.
  /// @param format the the [CryptoBinaryFormat] to use.
  /// @return the serialized binary data.
  byte[] asData(PAIR keyPair, String format);

  @Override
  default PAIR createKeyPair(byte[] data) {

    return createKeyPair(data, CryptoBinaryFormat.FORMAT_COMPACT);
  }

  /// @param data the [AsymmetricKeyPair] as raw byte array.
  /// @param format the the [CryptoBinaryFormat] to use.
  /// @return the deserialized [AsymmetricKeyPair].
  PAIR createKeyPair(byte[] data, String format);

  /// @param privateKey the [PrivateKey].
  /// @return the [key length][#getKeyLength()] of the given key in bits.
  int getKeyLength(PR privateKey);

  /// Verify that the given key matches the criteria of this key creator such as [key length][#getKeyLength()].
  ///
  /// @param privateKey the [PrivateKey] to verify.
  default void verifyKey(PR privateKey) {

    int givenKeyLength = getKeyLength(privateKey);
    int expectedKeyLength = getKeyLength();
    if (givenKeyLength != expectedKeyLength) {
      throw new IllegalArgumentException(
          "Private key has a length of " + givenKeyLength + " bits but expected " + expectedKeyLength + " bits!");
    }
  }

  /// @param publicKey the [PublicKey].
  /// @return the [key length][#getKeyLength()] of the given key in bits.
  int getKeyLength(PU publicKey);

  /// Verify that the given key matches the criteria of this key creator such as [key length][#getKeyLength()].
  ///
  /// @param publicKey the [PublicKey] to verify.
  default void verifyKey(PU publicKey) {

    int givenKeyLength = getKeyLength(publicKey);
    int expectedKeyLength = getKeyLength();
    if (givenKeyLength != expectedKeyLength) {
      throw new IllegalArgumentException(
          "Public key has a length of " + givenKeyLength + " bits but expected " + expectedKeyLength + " bits!");
    }
  }

}
