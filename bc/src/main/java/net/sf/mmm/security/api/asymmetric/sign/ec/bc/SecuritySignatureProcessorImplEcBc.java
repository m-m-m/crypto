package net.sf.mmm.security.api.asymmetric.sign.ec.bc;

import net.sf.mmm.security.api.asymmetric.sign.SecuritySignature;
import net.sf.mmm.security.api.asymmetric.sign.SecuritySignatureConfig;
import net.sf.mmm.security.api.asymmetric.sign.SecuritySignatureProcessor;
import net.sf.mmm.security.api.asymmetric.sign.SecuritySignatureSigner;
import net.sf.mmm.security.api.asymmetric.sign.ec.SecuritySignatureConfigEcDsa;

import org.bouncycastle.crypto.signers.ECDSASigner;

/**
 * Implementation of {@link SecuritySignatureSigner}.
 *
 * @param <S> type of {@link SecuritySignature}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class SecuritySignatureProcessorImplEcBc<S extends SecuritySignatureEcBc> implements SecuritySignatureProcessor {

  private final SecuritySignatureConfig<S> config;

  private final SecuritySignatureFactoryEcBc<S> signatureFactory;

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
  public SecuritySignatureProcessorImplEcBc(SecuritySignatureConfigEcDsa<S> config, ECDSASigner signer) {

    super();
    this.config = config;
    this.signatureFactory = (SecuritySignatureFactoryEcBc<S>) config.getSignatureFactory();
    this.signer = signer;
  }

  @Override
  public String getAlgorithm() {

    return this.config.getAlgorithm();
  }

  /**
   * @return the {@link SecuritySignatureConfig}.
   */
  public SecuritySignatureConfig<S> getConfig() {

    return this.config;
  }

  /**
   * @return the {@link SecuritySignatureFactoryEcBc}.
   */
  public SecuritySignatureFactoryEcBc<S> getSignatureFactory() {

    return this.signatureFactory;
  }

  @Override
  public void update(byte[] input, int offset, int length) {

    if (this.data != null) {
      throw new IllegalStateException("This implementation does not allow sequential updating. Please combine with hash algorithm.");
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
