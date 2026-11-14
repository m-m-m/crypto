package io.github.mmm.crypto.asymmetric.sign;

import io.github.mmm.crypto.algorithm.AbstractSecurityAlgorithm;
import io.github.mmm.crypto.algorithm.CryptoAlgorithm;
import io.github.mmm.crypto.hash.HashCreator;

/// Implementation of [SignatureProcessor] combining a [SignatureSigner] with a
/// [HashCreator].
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public abstract class SignatureProcessorImplWithHash extends AbstractSecurityAlgorithm implements SignatureProcessor {

  private final HashCreator hashGenerator;

  /// The constructor.
  ///
  /// @param hashGenerator the [HashCreator] to apply as extension.
  public SignatureProcessorImplWithHash(HashCreator hashGenerator) {

    super();
    this.hashGenerator = hashGenerator;
  }

  /// @return the [CryptoAlgorithm] to extend.
  protected abstract CryptoAlgorithm getSignatureAlgorithm();

  /// @return the [HashCreator] to apply as extension.
  protected HashCreator getHashGenerator() {

    return this.hashGenerator;
  }

  @Override
  public String getAlgorithm() {

    return this.hashGenerator.getAlgorithm() + "+" + getSignatureAlgorithm().getAlgorithm();
  }

  @Override
  public void update(byte[] input, int offset, int length) {

    this.hashGenerator.update(input, offset, length);
  }

  @Override
  public void reset() {

    this.hashGenerator.reset();
  }

}
