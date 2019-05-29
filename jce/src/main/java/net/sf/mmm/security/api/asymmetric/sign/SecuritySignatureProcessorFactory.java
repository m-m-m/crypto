package net.sf.mmm.security.api.asymmetric.sign;

import java.security.PrivateKey;
import java.security.PublicKey;

import net.sf.mmm.security.api.AbstractSecurityFactory;

/**
 * Interface for a {@link AbstractSecurityFactory factory} to create instances of {@link SecuritySignatureProcessor} for
 * {@link net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyPair asymmetric cryptography}.
 * {@link SecuritySignature Signatures} only work with asymmetric security. For a given {@link PrivateKey private key} a
 * {@link SecuritySignatureSigner} can be {@link #newSigner(PrivateKey) created} that allows to
 * {@link SecuritySignatureSigner#sign(byte[], boolean) sign} any message. With the corresponding {@link PublicKey
 * public key} anyone can {@link #newVerifier(PublicKey) create} a {@link SecuritySignatureVerifier} to
 * {@link SecuritySignatureVerifier#verify(byte[], SecuritySignature) verify} the {@link SecuritySignature}.<br>
 * An instance of {@link SecuritySignatureProcessorFactory} typically combines asymmetric
 * {@link net.sf.mmm.security.api.crypt.SecurityCryptor cryptography} with
 * {@link net.sf.mmm.security.api.hash.SecurityHashCreator hashing}.
 *
 * @param <S> type of {@link SecuritySignature}.
 * @param <PR> type of {@link PrivateKey}.
 * @param <PU> type of {@link PublicKey}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecuritySignatureProcessorFactory<S extends SecuritySignature, PR extends PrivateKey, PU extends PublicKey>
    extends SecuritySignatureFactory<S> {

  /**
   * @param privateKey the {@link PrivateKey} to use for signing.
   * @return the {@link SecuritySignatureSigner} for signing.
   */
  @SuppressWarnings("unchecked")
  default SecuritySignatureSigner<S> newSignerUnsafe(PrivateKey privateKey) {

    return newSigner((PR) privateKey);
  }

  /**
   * @param privateKey the {@link PrivateKey} to use for signing.
   * @return the {@link SecuritySignatureSigner} for signing.
   */
  SecuritySignatureSigner<S> newSigner(PR privateKey);

  /**
   * @param publicKey the {@link PublicKey} to use for verifying.
   * @return the {@link SecuritySignatureVerifier} for verifying.
   */
  @SuppressWarnings("unchecked")
  default SecuritySignatureVerifier<S> newVerifierUnsafe(PublicKey publicKey) {

    return newVerifier((PU) publicKey);
  }

  /**
   * @param publicKey the {@link PublicKey} to use for verifying.
   * @return the {@link SecuritySignatureVerifier} for verifying.
   */
  SecuritySignatureVerifier<S> newVerifier(PU publicKey);

  /**
   * @return an instance of this {@link SecuritySignatureFactory} that does not hash before signing so you can control
   *         the hashing manually and only sign the resulting hash (e.g. to reuse the hash value for further
   *         calculations).
   */
  SecuritySignatureProcessorFactory<S, PR, PU> getSignatureFactoryWithoutHash();
}
