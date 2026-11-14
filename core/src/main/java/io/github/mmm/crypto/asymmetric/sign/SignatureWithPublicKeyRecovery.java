package io.github.mmm.crypto.asymmetric.sign;

import java.security.PublicKey;

import io.github.mmm.binary.Binary;

/// Interface for [SignatureBinary] that allows to [recover public key][#recoverPublicKey(byte[])].
///
/// @since 1.0.0
public interface SignatureWithPublicKeyRecovery extends Binary {
  /// @param message the payload (typically hash of message) that was signed when this signature was created.
  /// @return the recovered public key.
  public PublicKey recoverPublicKey(byte[] message);

}
