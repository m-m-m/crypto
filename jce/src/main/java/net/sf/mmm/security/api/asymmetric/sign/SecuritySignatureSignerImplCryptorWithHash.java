package net.sf.mmm.security.api.asymmetric.sign;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithm;
import net.sf.mmm.security.api.asymmetric.sign.generic.SecuritySignatureGeneric;
import net.sf.mmm.security.api.crypt.SecurityEncryptor;
import net.sf.mmm.security.api.hash.SecurityHashCreator;

/**
 * Implementation of {@link SecuritySignatureSigner} combining a {@link SecurityEncryptor} with a
 * {@link SecurityHashCreator}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecuritySignatureSignerImplCryptorWithHash extends SecuritySignatureProcessorImplWithHash
    implements SecuritySignatureSigner<SecuritySignature> {

  private final SecurityEncryptor encryptor;

  /**
   * The constructor.
   *
   * @param hashGenerator the {@link SecurityHashCreator} to apply as extension.
   * @param encryptor the {@link SecurityEncryptor} to use.
   */
  public SecuritySignatureSignerImplCryptorWithHash(SecurityHashCreator hashGenerator, SecurityEncryptor encryptor) {

    super(hashGenerator);
    this.encryptor = encryptor;
  }

  @Override
  protected SecurityAlgorithm getSignatureAlgorithm() {

    return this.encryptor;
  }

  @Override
  public SecuritySignatureGeneric signAfterUpdate(boolean reset) {

    return new SecuritySignatureGeneric(signAfterUpdateRaw(reset));
  }

  @Override
  public byte[] signAfterUpdateRaw(boolean reset) {

    byte[] hash = getHashGenerator().hash(true);
    byte[] signature = this.encryptor.process(hash);
    if (reset) {
      reset();
    }
    return signature;
  }

  @Override
  public void reset() {

    super.reset();
    this.encryptor.reset();
  }

}
