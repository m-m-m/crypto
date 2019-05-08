package net.sf.mmm.security.api.asymmetric.sign;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithm;
import net.sf.mmm.security.api.hash.SecurityHashCreator;

/**
 * Implementation of {@link SecuritySignatureSigner} combining a {@link SecurityHashCreator} with another
 * {@link SecuritySignatureSigner}.
 *
 * @param <S> type of {@link SecuritySignature}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecuritySignatureSignerImplWithHash<S extends SecuritySignature> extends SecuritySignatureProcessorImplWithHash
    implements SecuritySignatureSigner<S> {

  private final SecuritySignatureSigner<S> signer;

  /**
   * The constructor.
   *
   * @param hashGenerator the {@link SecurityHashCreator} to apply as extension.
   * @param signer the {@link SecuritySignatureSigner} to extend.
   */
  public SecuritySignatureSignerImplWithHash(SecurityHashCreator hashGenerator, SecuritySignatureSigner<S> signer) {

    super(hashGenerator);
    this.signer = signer;
  }

  @Override
  protected SecurityAlgorithm getSignatureAlgorithm() {

    return this.signer;
  }

  @Override
  public S signAfterUpdate(boolean reset) {

    byte[] hash = getHashGenerator().hash(true);
    return this.signer.sign(hash, reset);
  }

  @Override
  public byte[] signAfterUpdateRaw(boolean reset) {

    byte[] hash = getHashGenerator().hash(true);
    this.signer.update(hash);
    byte[] signature = this.signer.signAfterUpdateRaw(reset);
    return signature;
  }

  @Override
  public void reset() {

    super.reset();
    this.signer.reset();
  }

}
