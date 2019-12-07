package io.github.mmm.crypto.asymmetric.sign;

import java.security.PrivateKey;
import java.security.PublicKey;

import io.github.mmm.crypto.hash.HashCreator;
import io.github.mmm.crypto.hash.HashFactory;

/**
 * Implementation of {@link SignatureProcessorFactory} combining a {@link SignatureProcessor} with a
 * {@link HashCreator}.
 *
 * @param <S> type of {@link SignatureBinary}.
 * @param <PR> type of {@link PrivateKey}.
 * @param <PU> type of {@link PublicKey}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SignatureProcessorFactoryImplWithHash<S extends SignatureBinary, PR extends PrivateKey, PU extends PublicKey>
    implements SignatureProcessorFactory<S, PR, PU> {

  private final SignatureProcessorFactory<S, PR, PU> signatureFactory;

  private final HashFactory hashFactory;

  /**
   * The constructor.
   *
   * @param signatureFactory the {@link SignatureProcessorFactory} to delegate to.
   * @param hashFactory the {@link HashFactory} to apply before signing or verifying.
   */
  public SignatureProcessorFactoryImplWithHash(SignatureProcessorFactory<S, PR, PU> signatureFactory,
      HashFactory hashFactory) {

    super();
    this.signatureFactory = signatureFactory;
    this.hashFactory = hashFactory;
  }

  @Override
  public SignatureSigner<S> newSigner(PR privateKey) {

    return new SignatureSignerImplWithHash<>(this.hashFactory.newHashCreator(), this.signatureFactory.newSigner(privateKey));
  }

  @Override
  public SignatureVerifier<S> newVerifier(PU publicKey) {

    return new SignatureVerifierImplWithHash<>(this.hashFactory.newHashCreator(), this.signatureFactory.newVerifier(publicKey));
  }

  @Override
  public S createSignature(byte[] data) {

    return this.signatureFactory.createSignature(data);
  }

  @Override
  public SignatureProcessorFactory<S, PR, PU> getSignatureFactoryWithoutHash() {

    return this.signatureFactory;
  }

  @Override
  public String toString() {

    return this.hashFactory.toString() + "+" + this.signatureFactory.toString();
  }

}
