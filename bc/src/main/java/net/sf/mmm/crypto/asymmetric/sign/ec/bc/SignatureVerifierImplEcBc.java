package net.sf.mmm.crypto.asymmetric.sign.ec.bc;

import net.sf.mmm.crypto.asymmetric.sign.SignatureBinary;
import net.sf.mmm.crypto.asymmetric.sign.SignatureSigner;
import net.sf.mmm.crypto.asymmetric.sign.SignatureVerifier;
import net.sf.mmm.crypto.asymmetric.sign.ec.SignatureConfigEcDsa;

import org.bouncycastle.crypto.signers.ECDSASigner;

/**
 * Implementation of {@link SignatureSigner}.
 *
 * @param <S> type of {@link SignatureBinary}.
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
