package net.sf.mmm.crypto.asymmetric.key;

import java.security.PrivateKey;

import net.sf.mmm.binary.api.Binary;
import net.sf.mmm.crypto.CryptBinary;

/**
 * Interface for factory to create instances of {@link PrivateKey}.
 *
 * @see AsymmetricKeyCreator
 *
 * @param <PR> type of {@link PrivateKey}.
 * @since 1.0.0
 */
public interface PrivateKeyFactory<PR extends PrivateKey> {

  /**
   * @param privateKey the {@link PrivateKey} to serialize.
   * @return the serialized {@link Binary}.
   */
  default Binary asBinary(PR privateKey) {

    return new CryptBinary(asData(privateKey));
  }

  /**
   * @param privateKey the {@link PrivateKey} to serialize.
   * @return the serialized binary data.
   */
  byte[] asData(PR privateKey);

  /**
   * @param data the {@link PrivateKey} as raw {@code byte} array.
   * @return the deserialized {@link PrivateKey}.
   */
  PR createPrivateKey(byte[] data);

}
