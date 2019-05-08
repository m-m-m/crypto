package net.sf.mmm.security.api.asymmetric.sign;

import net.sf.mmm.security.api.hash.SecurityHashCreator;

/**
 * Implementation of {@link SecuritySignatureVerifier} combining a {@link SecuritySignatureVerifier} with a
 * {@link SecurityHashCreator}.
 *
 * @param <S> type of {@link SecuritySignature}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecuritySignatureVerifierImplWithHash<S extends SecuritySignature> extends SecuritySignatureProcessorImplWithHash
    implements SecuritySignatureVerifier<S> {

  private final SecuritySignatureVerifier<S> verifier;

  /**
   * The constructor.
   *
   * @param hashGenerator the {@link SecurityHashCreator} to apply as extension.
   * @param verifier the {@link SecuritySignatureVerifier} to extend.
   */
  public SecuritySignatureVerifierImplWithHash(SecurityHashCreator hashGenerator, SecuritySignatureVerifier<S> verifier) {

    super(hashGenerator);
    this.verifier = verifier;
  }

  @Override
  protected SecuritySignatureVerifier<S> getSignatureAlgorithm() {

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
