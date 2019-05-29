package net.sf.mmm.crypto.asymmetric.sign;

import java.util.Arrays;

import net.sf.mmm.crypto.crypt.Decryptor;
import net.sf.mmm.crypto.hash.HashCreator;

/**
 * Implementation of {@link SignatureVerifier} combining a {@link Decryptor} with a
 * {@link HashCreator}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SignatureVerifierImplCryptorWithHash extends SignatureProcessorImplWithHash
    implements SignatureVerifier<SignatureBinary> {

  private final Decryptor decryptor;

  /**
   * The constructor.
   *
   * @param hashGenerator the {@link HashCreator} to apply as extension.
   * @param decryptor the {@link Decryptor} to extend.
   */
  public SignatureVerifierImplCryptorWithHash(HashCreator hashGenerator, Decryptor decryptor) {

    super(hashGenerator);
    this.decryptor = decryptor;
  }

  @Override
  protected Decryptor getSignatureAlgorithm() {

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
