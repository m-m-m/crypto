package net.sf.mmm.crypto.asymmetric.sign;

import java.security.Signature;
import java.security.SignatureException;

/**
 * Implementation of {@link SignatureSigner}.
 *
 * @param <S> type of {@link SignatureBinary}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SignatureSignerImpl<S extends SignatureBinary> extends SignatureProcessorImpl
    implements SignatureSigner<S> {

  private SignatureFactory<S> factory;

  /**
   * The constructor.
   *
   * @param signature the underlying {@link Signature}.
   * @param factory the {@link SignatureFactory}.
   */
  public SignatureSignerImpl(Signature signature, SignatureFactory<S> factory) {

    super(signature);
    this.factory = factory;
  }

  @Override
  public S signAfterUpdate(boolean reset) {

    return createSignature(signAfterUpdateRaw(reset));
  }

  /**
   * @param signatureData the {@link #signAfterUpdateRaw(boolean) raw signature}.
   * @return the {@link SignatureBinary}.
   */
  protected S createSignature(byte[] signatureData) {

    return this.factory.createSignature(signatureData);
  }

  @Override
  public byte[] signAfterUpdateRaw(boolean reset) {

    try {
      byte[] signature = getSignature().sign();
      if (reset) {
        reset();
      }
      return signature;
    } catch (SignatureException e) {
      throw creationFailedException(e, Signature.class);
    }
  }

}
