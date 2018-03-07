package net.sf.mmm.security.impl.sign;

import net.sf.mmm.security.api.hash.SecurityHashCreator;
import net.sf.mmm.security.api.sign.SecuritySignatureVerifier;

/**
 * Implementation of {@link SecuritySignatureVerifier} combining a {@link SecuritySignatureVerifier} with a
 * {@link SecurityHashCreator}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecuritySignatureVerifierImplWithHash extends SecuritySignatureGeneratorImplWithHash
    implements SecuritySignatureVerifier {

  private final SecuritySignatureVerifier verifier;

  /**
   * The constructor.
   *
   * @param hashGenerator the {@link SecurityHashCreator} to apply as extension.
   * @param verifier the {@link SecuritySignatureVerifier} to extend.
   */
  public SecuritySignatureVerifierImplWithHash(SecurityHashCreator hashGenerator, SecuritySignatureVerifier verifier) {
    super(hashGenerator);
    this.verifier = verifier;
  }

  @Override
  protected SecuritySignatureVerifier getSignatureAlgorithm() {

    return this.verifier;
  }

  @Override
  public boolean verifyAfterUpdate(byte[] signature, int offset, int length) {

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
