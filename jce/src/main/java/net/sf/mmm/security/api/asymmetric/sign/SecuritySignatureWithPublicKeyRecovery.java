package net.sf.mmm.security.api.asymmetric.sign;

import java.security.PublicKey;

import net.sf.mmm.binary.api.Binary;

/**
 * Interface for {@link SecuritySignature} that allows to {@link #recoverPublicKey(byte[]) recover public key}.
 *
 * @since 1.0.0
 */
public interface SecuritySignatureWithPublicKeyRecovery extends Binary {
  /**
   * @param message the payload (typically hash of message) that was signed when this signature was created.
   * @return the recovered public key.
   */
  public PublicKey recoverPublicKey(byte[] message);

}
