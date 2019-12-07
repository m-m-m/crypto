package io.github.mmm.crypto.asymmetric.sign;

import io.github.mmm.crypto.algorithm.CryptoAlgorithm;
import io.github.mmm.crypto.asymmetric.sign.generic.SignatureGeneric;
import io.github.mmm.crypto.crypt.Encryptor;
import io.github.mmm.crypto.hash.HashCreator;

/**
 * Implementation of {@link SignatureSigner} combining a {@link Encryptor} with a
 * {@link HashCreator}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SignatureSignerImplCryptorWithHash extends SignatureProcessorImplWithHash
    implements SignatureSigner<SignatureBinary> {

  private final Encryptor encryptor;

  /**
   * The constructor.
   *
   * @param hashGenerator the {@link HashCreator} to apply as extension.
   * @param encryptor the {@link Encryptor} to use.
   */
  public SignatureSignerImplCryptorWithHash(HashCreator hashGenerator, Encryptor encryptor) {

    super(hashGenerator);
    this.encryptor = encryptor;
  }

  @Override
  protected CryptoAlgorithm getSignatureAlgorithm() {

    return this.encryptor;
  }

  @Override
  public SignatureGeneric signAfterUpdate(boolean reset) {

    return new SignatureGeneric(signAfterUpdateRaw(reset));
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
