package io.github.mmm.crypto.asymmetric.key;

import java.security.PrivateKey;
import java.security.PublicKey;

import io.github.mmm.binary.Binary;
import io.github.mmm.crypto.CryptoBinary;

/**
 * Interface for factory to create instances of {@link AsymmetricKeyPair}, {@link PrivateKey}, and {@link PublicKey}. It
 * shall only be used internally (as SPI). End-users shall use {@link AsymmetricKeyCreator}.
 *
 * @param <PR> type of {@link PrivateKey}.
 * @param <PU> type of {@link PublicKey}.
 * @param <PAIR> type of {@link AsymmetricKeyPair}.
 * @since 1.0.0
 */
public interface AsymmetricKeyPairFactory<PR extends PrivateKey, PU extends PublicKey, PAIR extends AsymmetricKeyPair<PR, PU>>
    extends PrivateKeyFactory<PR>, PublicKeyFactory<PU>, AsymmetricKeyPairFactorySimple<PR, PU, PAIR> {

  /**
   * @param keyPair the {@link AsymmetricKeyPair} to serialize.
   * @return the serialized {@link Binary}.
   */
  default Binary asBinary(PAIR keyPair) {

    return new CryptoBinary(asData(keyPair));
  }

  /**
   * @param keyPair the {@link AsymmetricKeyPair} to serialize.
   * @return the serialized binary data.
   */
  byte[] asData(PAIR keyPair);

  /**
   * @param data the {@link AsymmetricKeyPair} in its binary form.
   * @return the deserialized {@link AsymmetricKeyPair}.
   */
  PAIR createKeyPair(byte[] data);

}
