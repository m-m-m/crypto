package net.sf.mmm.security.api.asymmetric.sign;

import java.security.Signature;

import net.sf.mmm.security.api.algorithm.AbstractSecurityAlgorithm;

/**
 * Implementation of {@link SecuritySignatureProcessor} based on {@link Signature}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class SecuritySignatureProcessorImpl extends AbstractSecurityAlgorithm implements SecuritySignatureProcessor {

  private final Signature signature;

  /**
   * The constructor.
   *
   * @param signature the {@link Signature} to use.
   */
  public SecuritySignatureProcessorImpl(Signature signature) {

    super();
    this.signature = signature;
  }

  /**
   * @return the underlying {@link Signature}.
   */
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
