package net.sf.mmm.security.api.asymmetric.key;

import java.security.PrivateKey;
import java.security.PublicKey;

import net.sf.mmm.binary.api.Binary;
import net.sf.mmm.security.api.SecurityBinaryType;

/**
 * Interface for factory to create instances of {@link SecurityAsymmetricKeyPair}, {@link PrivateKey}, and
 * {@link PublicKey}. It shall only be used internally (as SPI). End-users shall use
 * {@link SecurityAsymmetricKeyCreator}.
 *
 * @param <PR> type of {@link PrivateKey}.
 * @param <PU> type of {@link PublicKey}.
 * @param <PAIR> type of {@link SecurityAsymmetricKeyPair}.
 * @since 1.0.0
 */
public interface SecurityAsymmetricKeyPairFactory<PR extends PrivateKey, PU extends PublicKey, PAIR extends SecurityAsymmetricKeyPair<PR, PU>>
    extends SecurityPrivateKeyFactory<PR>, SecurityPublicKeyFactory<PU>, SecurityAsymmetricKeyPairFactorySimple<PR, PU, PAIR> {

  /**
   * @param keyPair the {@link SecurityAsymmetricKeyPair} to serialize.
   * @return the serialized {@link Binary}.
   */
  default Binary asBinary(PAIR keyPair) {

    return new SecurityBinaryType(asData(keyPair));
  }

  /**
   * @param keyPair the {@link SecurityAsymmetricKeyPair} to serialize.
   * @return the serialized binary data.
   */
  byte[] asData(PAIR keyPair);

  /**
   * @param data the {@link SecurityAsymmetricKeyPair} in its binary form.
   * @return the deserialized {@link SecurityAsymmetricKeyPair}.
   */
  PAIR createKeyPair(byte[] data);

}
