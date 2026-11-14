package io.github.mmm.crypto.asymmetric.sign;

import java.util.Arrays;

import io.github.mmm.crypto.crypt.Decryptor;
import io.github.mmm.crypto.hash.HashCreator;

/// Implementation of [SignatureVerifier] combining a [Decryptor] with a
/// [HashCreator].
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public class SignatureVerifierImplCryptorWithHash extends SignatureProcessorImplWithHash
    implements SignatureVerifier<SignatureBinary> {

  private final Decryptor decryptor;

  /// The constructor.
  ///
  /// @param hashGenerator the [HashCreator] to apply as extension.
  /// @param decryptor the [Decryptor] to extend.
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
