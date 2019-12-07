package io.github.mmm.crypto.asymmetric.sign.ec.bc;

import org.bouncycastle.crypto.signers.ECDSASigner;

import io.github.mmm.crypto.asymmetric.sign.SignatureVerifier;
import io.github.mmm.crypto.asymmetric.sign.ec.SignatureConfigEcDsa;

/**
 * Implementation of {@link SignatureVerifier} for {@link SignatureEcBc}.
 *
 * @param <S> type of {@link SignatureEcBc}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SignatureVerifierImplEcBc<S extends SignatureEcBc> extends SignatureProcessorImplEcBc<S>
    implements SignatureVerifier<S> {

  /**
   * The constructor.
   *
   * @param config the {@link #getConfig() config}.
   * @param signer the underlying {@link ECDSASigner}.
   */
  public SignatureVerifierImplEcBc(SignatureConfigEcDsa<S> config, ECDSASigner signer) {

    super(config, signer);
  }

  @Override
  public boolean verifyAfterUpdate(S signature) {

    if (this.data == null) {
      throw new IllegalStateException("No data was specified to verify!");
    }
    return this.signer.verifySignature(this.data, signature.getR(), signature.getS());
  }

  @Override
  public boolean verifyAfterUpdate(byte[] signature, int offset, int length) {

    byte[] signatureData;
    if ((offset == 0) && (length == signature.length)) {
      signatureData = signature;
    } else {
      signatureData = new byte[length];
      System.arraycopy(signature, offset, signatureData, 0, length);
    }
    return verifyAfterUpdate(getSignatureFactory().createSignature(signatureData));
  }

}
