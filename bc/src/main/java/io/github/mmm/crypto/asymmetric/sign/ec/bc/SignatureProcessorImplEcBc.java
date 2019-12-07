package io.github.mmm.crypto.asymmetric.sign.ec.bc;

import org.bouncycastle.crypto.signers.ECDSASigner;

import io.github.mmm.crypto.asymmetric.sign.SignatureConfig;
import io.github.mmm.crypto.asymmetric.sign.SignatureProcessor;
import io.github.mmm.crypto.asymmetric.sign.ec.SignatureConfigEcDsa;

/**
 * Implementation of {@link io.github.mmm.crypto.asymmetric.sign.SignatureSigner}.
 *
 * @param <S> type of {@link SignatureEcBc}.
 * @since 1.0.0
 */
public abstract class SignatureProcessorImplEcBc<S extends SignatureEcBc> implements SignatureProcessor {

  private final SignatureConfig<S> config;

  private final SignatureFactoryEcBc<S> signatureFactory;

  /** The {@link ECDSASigner}. */
  protected final ECDSASigner signer;

  /** The binary data to sign. */
  protected byte[] data;

  /**
   * The constructor.
   *
   * @param config the {@link #getConfig() config}.
   * @param signer the underlying {@link ECDSASigner}.
   */
  public SignatureProcessorImplEcBc(SignatureConfigEcDsa<S> config, ECDSASigner signer) {

    super();
    this.config = config;
    this.signatureFactory = (SignatureFactoryEcBc<S>) config.getSignatureFactory();
    this.signer = signer;
  }

  @Override
  public String getAlgorithm() {

    return this.config.getAlgorithm();
  }

  /**
   * @return the {@link SignatureConfig}.
   */
  public SignatureConfig<S> getConfig() {

    return this.config;
  }

  /**
   * @return the {@link SignatureFactoryEcBc}.
   */
  public SignatureFactoryEcBc<S> getSignatureFactory() {

    return this.signatureFactory;
  }

  @Override
  public void update(byte[] input, int offset, int length) {

    if (this.data != null) {
      throw new IllegalStateException(
          "This implementation does not allow sequential updating. Please combine with hash algorithm.");
    }
    if ((offset == 0) && (length == input.length)) {
      this.data = input;
    } else {
      this.data = new byte[length];
      System.arraycopy(input, offset, this.data, 0, length);
    }
  }

  @Override
  public void reset() {

    // nothing to do
  }

}
