package net.sf.mmm.security.api.asymmetric.key;

import java.security.PrivateKey;

import net.sf.mmm.binary.api.Binary;
import net.sf.mmm.security.api.SecurityBinaryType;

/**
 * Interface for factory to create instances of {@link PrivateKey}.
 *
 * @see SecurityAsymmetricKeyCreator
 *
 * @param <PR> type of {@link PrivateKey}.
 * @since 1.0.0
 */
public interface SecurityPrivateKeyFactory<PR extends PrivateKey> {

  /**
   * @param privateKey the {@link PrivateKey} to serialize.
   * @return the serialized {@link Binary}.
   */
  default Binary asBinary(PR privateKey) {

    return new SecurityBinaryType(asData(privateKey));
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
