package io.github.mmm.crypto.asymmetric.sign;

import java.security.PrivateKey;
import java.security.PublicKey;

import io.github.mmm.crypto.AbstractCryptoFactory;

/// Interface for a [factory][AbstractCryptoFactory] to create instances of [SignatureProcessor] for
/// [asymmetric cryptography][io.github.mmm.crypto.asymmetric.key.AsymmetricKeyPair].
/// [Signatures][SignatureBinary] only work with asymmetric security. For a given [private key][PrivateKey] a
/// [SignatureSigner] can be [created][#newSigner(PrivateKey)] that allows to
/// [sign][SignatureSigner#sign(byte[], boolean)] any message. With the corresponding [public key][PublicKey] anyone can [create][#newVerifier(PublicKey)] a [SignatureVerifier] to
/// [verify][SignatureVerifier#verify(byte[], SignatureBinary)] the [SignatureBinary].
/// An instance of [SignatureProcessorFactory] typically combines asymmetric
/// [cryptography][io.github.mmm.crypto.crypt.Cryptor] with
/// [hashing][io.github.mmm.crypto.hash.HashCreator].
///
/// @param <S> type of [SignatureBinary].
/// @param <PR> type of [PrivateKey].
/// @param <PU> type of [PublicKey].
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public interface SignatureProcessorFactory<S extends SignatureBinary, PR extends PrivateKey, PU extends PublicKey>
    extends SignatureFactory<S> {

  /// @param privateKey the [PrivateKey] to use for signing.
  /// @return the [SignatureSigner] for signing.
  @SuppressWarnings("unchecked")
  default SignatureSigner<S> newSignerUnsafe(PrivateKey privateKey) {

    return newSigner((PR) privateKey);
  }

  /// @param privateKey the [PrivateKey] to use for signing.
  /// @return the [SignatureSigner] for signing.
  SignatureSigner<S> newSigner(PR privateKey);

  /// @param publicKey the [PublicKey] to use for verifying.
  /// @return the [SignatureVerifier] for verifying.
  @SuppressWarnings("unchecked")
  default SignatureVerifier<S> newVerifierUnsafe(PublicKey publicKey) {

    return newVerifier((PU) publicKey);
  }

  /// @param publicKey the [PublicKey] to use for verifying.
  /// @return the [SignatureVerifier] for verifying.
  SignatureVerifier<S> newVerifier(PU publicKey);

  /// @return an instance of this [SignatureFactory] that does not hash before signing so you can control
  ///         the hashing manually and only sign the resulting hash (e.g. to reuse the hash value for further
  ///         calculations).
  SignatureProcessorFactory<S, PR, PU> getSignatureFactoryWithoutHash();
}
