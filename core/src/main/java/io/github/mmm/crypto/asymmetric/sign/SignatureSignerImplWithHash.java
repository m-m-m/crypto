package io.github.mmm.crypto.asymmetric.sign;

import io.github.mmm.crypto.algorithm.CryptoAlgorithm;
import io.github.mmm.crypto.hash.HashCreator;

/// Implementation of [SignatureSigner] combining a [HashCreator] with another
/// [SignatureSigner].
///
/// @param <S> type of [SignatureBinary].
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public class SignatureSignerImplWithHash<S extends SignatureBinary> extends SignatureProcessorImplWithHash
    implements SignatureSigner<S> {

  private final SignatureSigner<S> signer;

  /// The constructor.
  ///
  /// @param hashGenerator the [HashCreator] to apply as extension.
  /// @param signer the [SignatureSigner] to extend.
  public SignatureSignerImplWithHash(HashCreator hashGenerator, SignatureSigner<S> signer) {

    super(hashGenerator);
    this.signer = signer;
  }

  @Override
  protected CryptoAlgorithm getSignatureAlgorithm() {

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
