package net.sf.mmm.crypto.asymmetric.sign;

import java.security.PrivateKey;
import java.security.PublicKey;

import net.sf.mmm.crypto.AbstractCryptoFactory;

/**
 * Interface for a {@link AbstractCryptoFactory factory} to create instances of {@link SignatureProcessor} for
 * {@link net.sf.mmm.crypto.asymmetric.key.AsymmetricKeyPair asymmetric cryptography}.
 * {@link SignatureBinary Signatures} only work with asymmetric security. For a given {@link PrivateKey private key} a
 * {@link SignatureSigner} can be {@link #newSigner(PrivateKey) created} that allows to
 * {@link SignatureSigner#sign(byte[], boolean) sign} any message. With the corresponding {@link PublicKey
 * public key} anyone can {@link #newVerifier(PublicKey) create} a {@link SignatureVerifier} to
 * {@link SignatureVerifier#verify(byte[], SignatureBinary) verify} the {@link SignatureBinary}.<br>
 * An instance of {@link SignatureProcessorFactory} typically combines asymmetric
 * {@link net.sf.mmm.crypto.crypt.Cryptor cryptography} with
 * {@link net.sf.mmm.crypto.hash.HashCreator hashing}.
 *
 * @param <S> type of {@link SignatureBinary}.
 * @param <PR> type of {@link PrivateKey}.
 * @param <PU> type of {@link PublicKey}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SignatureProcessorFactory<S extends SignatureBinary, PR extends PrivateKey, PU extends PublicKey>
    extends SignatureFactory<S> {

  /**
   * @param privateKey the {@link PrivateKey} to use for signing.
   * @return the {@link SignatureSigner} for signing.
   */
  @SuppressWarnings("unchecked")
  default SignatureSigner<S> newSignerUnsafe(PrivateKey privateKey) {

    return newSigner((PR) privateKey);
  }

  /**
   * @param privateKey the {@link PrivateKey} to use for signing.
   * @return the {@link SignatureSigner} for signing.
   */
  SignatureSigner<S> newSigner(PR privateKey);

  /**
   * @param publicKey the {@link PublicKey} to use for verifying.
   * @return the {@link SignatureVerifier} for verifying.
   */
  @SuppressWarnings("unchecked")
  default SignatureVerifier<S> newVerifierUnsafe(PublicKey publicKey) {

    return newVerifier((PU) publicKey);
  }

  /**
   * @param publicKey the {@link PublicKey} to use for verifying.
   * @return the {@link SignatureVerifier} for verifying.
   */
  SignatureVerifier<S> newVerifier(PU publicKey);

  /**
   * @return an instance of this {@link SignatureFactory} that does not hash before signing so you can control
   *         the hashing manually and only sign the resulting hash (e.g. to reuse the hash value for further
   *         calculations).
   */
  SignatureProcessorFactory<S, PR, PU> getSignatureFactoryWithoutHash();
}
