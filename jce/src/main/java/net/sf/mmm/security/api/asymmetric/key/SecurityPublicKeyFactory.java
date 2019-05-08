package net.sf.mmm.security.api.asymmetric.key;

import java.security.PublicKey;

import net.sf.mmm.binary.api.Binary;
import net.sf.mmm.security.api.SecurityBinaryType;

/**
 * Interface for factory to create instances of {@link PublicKey}.
 *
 * @param <PU> type of {@link PublicKey}.
 * @since 1.0.0
 */
public interface SecurityPublicKeyFactory<PU extends PublicKey> {

  /**
   * @param publicKey the {@link PublicKey} to serialize.
   * @return the serialized {@link Binary}.
   */
  default Binary asBinary(PU publicKey) {

    return new SecurityBinaryType(asData(publicKey));
  }

  /**
   * @param publicKey the {@link PublicKey} to serialize.
   * @return the serialized binary data.
   */
  byte[] asData(PU publicKey);

  /**
   * @param data the {@link PublicKey} as raw {@code byte} array.
   * @return the deserialized {@link PublicKey}.
   */
  PU createPublicKey(byte[] data);

}