package io.github.mmm.crypto.asymmetric.sign;

import java.security.PublicKey;

import io.github.mmm.binary.Binary;

/**
 * Interface for {@link SignatureBinary} that allows to {@link #recoverPublicKey(byte[]) recover public key}.
 *
 * @since 1.0.0
 */
public interface SignatureWithPublicKeyRecovery extends Binary {
  /**
   * @param message the payload (typically hash of message) that was signed when this signature was created.
   * @return the recovered public key.
   */
  public PublicKey recoverPublicKey(byte[] message);

}
