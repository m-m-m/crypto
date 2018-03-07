package net.sf.mmm.security.impl.sign;

import java.util.Arrays;

import net.sf.mmm.security.api.crypt.SecurityDecryptor;
import net.sf.mmm.security.api.hash.SecurityHashCreator;
import net.sf.mmm.security.api.sign.SecuritySignatureVerifier;

/**
 * Implementation of {@link SecuritySignatureVerifier} combining a {@link SecurityDecryptor} with a
 * {@link SecurityHashCreator}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecuritySignatureVerifierImplCryptorWithHash extends SecuritySignatureGeneratorImplWithHash
    implements SecuritySignatureVerifier {

  private final SecurityDecryptor decryptor;

  /**
   * The constructor.
   *
   * @param hashGenerator the {@link SecurityHashCreator} to apply as extension.
   * @param decryptor the {@link SecurityDecryptor} to extend.
   */
  public SecuritySignatureVerifierImplCryptorWithHash(SecurityHashCreator hashGenerator, SecurityDecryptor decryptor) {
    super(hashGenerator);
    this.decryptor = decryptor;
  }

  @Override
  protected SecurityDecryptor getSignatureAlgorithm() {

    return this.decryptor;
  }

  @Override
  public boolean verifyAfterUpdate(byte[] signature, int offset, int length) {

    byte[] hash = getHashGenerator().hash(true);
    byte[] expectedHash = this.decryptor.crypt(signature, true);
    return Arrays.equals(hash, expectedHash);
  }

  @Override
  public void reset() {

    super.reset();
    this.decryptor.reset();
  }

}
