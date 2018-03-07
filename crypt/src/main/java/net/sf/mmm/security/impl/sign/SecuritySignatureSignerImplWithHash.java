package net.sf.mmm.security.impl.sign;

import net.sf.mmm.security.api.SecurityAlgorithmProcessor;
import net.sf.mmm.security.api.algorithm.SecurityAlgorithm;
import net.sf.mmm.security.api.crypt.SecurityEncryptor;
import net.sf.mmm.security.api.hash.SecurityHashCreator;
import net.sf.mmm.security.api.sign.SecuritySignatureSigner;

/**
 * Implementation of {@link SecuritySignatureSigner} combining a {@link SecurityEncryptor} or
 * {@link SecuritySignatureSigner} with a {@link SecurityHashCreator}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecuritySignatureSignerImplWithHash extends SecuritySignatureGeneratorImplWithHash implements SecuritySignatureSigner {

  private final SecurityAlgorithmProcessor signer;

  /**
   * The constructor.
   *
   * @param hashGenerator the {@link SecurityHashCreator} to apply as extension.
   * @param signer the {@link SecuritySignatureSigner} to extend.
   */
  public SecuritySignatureSignerImplWithHash(SecurityHashCreator hashGenerator, SecuritySignatureSigner signer) {

    this(signer, hashGenerator);
  }

  /**
   * The constructor.
   *
   * @param hashGenerator the {@link SecurityHashCreator} to apply as extension.
   * @param signer the {@link SecurityEncryptor} to extend.
   */
  public SecuritySignatureSignerImplWithHash(SecurityHashCreator hashGenerator, SecurityEncryptor signer) {

    this(signer, hashGenerator);
  }

  /**
   * The constructor.
   *
   * @param signer the {@link SecurityAlgorithmProcessor} to extend.
   * @param hashGenerator the {@link SecurityHashCreator} to apply as extension.
   */
  private SecuritySignatureSignerImplWithHash(SecurityAlgorithmProcessor signer, SecurityHashCreator hashGenerator) {

    super(hashGenerator);
    this.signer = signer;
  }

  @Override
  protected SecurityAlgorithm getSignatureAlgorithm() {

    return this.signer;
  }

  @Override
  public byte[] sign(boolean reset) {

    byte[] hash = getHashGenerator().hash(true);
    byte[] signature = this.signer.process(hash);
    if (reset) {
      reset();
    }
    return signature;
  }

  @Override
  public void reset() {

    super.reset();
    this.signer.reset();
  }

}
