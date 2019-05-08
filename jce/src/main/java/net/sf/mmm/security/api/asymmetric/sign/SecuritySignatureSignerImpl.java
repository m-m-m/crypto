package net.sf.mmm.security.api.asymmetric.sign;

import java.security.Signature;
import java.security.SignatureException;

/**
 * Implementation of {@link SecuritySignatureSigner}.
 *
 * @param <S> type of {@link SecuritySignature}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecuritySignatureSignerImpl<S extends SecuritySignature> extends SecuritySignatureProcessorImpl
    implements SecuritySignatureSigner<S> {

  private SecuritySignatureFactory<S> factory;

  /**
   * The constructor.
   *
   * @param signature the underlying {@link Signature}.
   * @param factory the {@link SecuritySignatureFactory}.
   */
  public SecuritySignatureSignerImpl(Signature signature, SecuritySignatureFactory<S> factory) {

    super(signature);
    this.factory = factory;
  }

  @Override
  public S signAfterUpdate(boolean reset) {

    return createSignature(signAfterUpdateRaw(reset));
  }

  /**
   * @param signatureData the {@link #signAfterUpdateRaw(boolean) raw signature}.
   * @return the {@link SecuritySignature}.
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
