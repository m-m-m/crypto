package io.github.mmm.crypto.asymmetric.sign;

import java.security.Signature;

import io.github.mmm.crypto.algorithm.AbstractSecurityAlgorithm;

/// Implementation of [SignatureProcessor] based on [Signature].
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public abstract class SignatureProcessorImpl extends AbstractSecurityAlgorithm implements SignatureProcessor {

  private final Signature signature;

  /// The constructor.
  ///
  /// @param signature the [Signature] to use.
  public SignatureProcessorImpl(Signature signature) {

    super();
    this.signature = signature;
  }

  /// @return the underlying [Signature].
  protected Signature getSignature() {

    return this.signature;
  }

  @Override
  public String getAlgorithm() {

    return this.signature.getAlgorithm();
  }

  @Override
  public void update(byte[] input, int offset, int length) {

    try {
      this.signature.update(input, offset, length);
    } catch (Exception e) {
      throw creationFailedException(e, Signature.class);
    }
  }

  @Override
  public void reset() {

    // nothing to do...
  }

}
