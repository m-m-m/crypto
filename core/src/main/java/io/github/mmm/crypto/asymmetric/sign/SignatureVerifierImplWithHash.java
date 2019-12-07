package io.github.mmm.crypto.asymmetric.sign;

import io.github.mmm.crypto.hash.HashCreator;

/**
 * Implementation of {@link SignatureVerifier} combining a {@link SignatureVerifier} with a
 * {@link HashCreator}.
 *
 * @param <S> type of {@link SignatureBinary}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SignatureVerifierImplWithHash<S extends SignatureBinary> extends SignatureProcessorImplWithHash
    implements SignatureVerifier<S> {

  private final SignatureVerifier<S> verifier;

  /**
   * The constructor.
   *
   * @param hashGenerator the {@link HashCreator} to apply as extension.
   * @param verifier the {@link SignatureVerifier} to extend.
   */
  public SignatureVerifierImplWithHash(HashCreator hashGenerator, SignatureVerifier<S> verifier) {

    super(hashGenerator);
    this.verifier = verifier;
  }

  @Override
  protected SignatureVerifier<S> getSignatureAlgorithm() {

    return this.verifier;
  }

  @Override
  public boolean verifyAfterUpdate(byte[] signature, int offset, int length) {

    byte[] hash = getHashGenerator().hash(true);
    this.verifier.update(hash);
    return this.verifier.verifyAfterUpdate(signature);
  }

  @Override
  public boolean verifyAfterUpdate(S signature) {

    byte[] hash = getHashGenerator().hash(true);
    this.verifier.update(hash);
    return this.verifier.verifyAfterUpdate(signature);
  }

  @Override
  public void reset() {

    super.reset();
    this.verifier.reset();
  }

}
