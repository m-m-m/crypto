package net.sf.mmm.security.api.asymmetric.sign.ec.bc;

import net.sf.mmm.security.api.asymmetric.sign.SecuritySignature;
import net.sf.mmm.security.api.asymmetric.sign.SecuritySignatureConfig;
import net.sf.mmm.security.api.asymmetric.sign.SecuritySignatureSigner;
import net.sf.mmm.security.api.asymmetric.sign.SecuritySignatureVerifier;

import org.bouncycastle.crypto.signers.ECDSASigner;

/**
 * Implementation of {@link SecuritySignatureSigner}.
 *
 * @param <S> type of {@link SecuritySignature}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecuritySignatureVerifierImplEcBc<S extends SecuritySignatureEcBc> extends SecuritySignatureProcessorImplEcBc<S>
    implements SecuritySignatureVerifier<S> {

  /**
   * The constructor.
   *
   * @param config the {@link #getConfig() config}.
   * @param signer the underlying {@link ECDSASigner}.
   */
  public SecuritySignatureVerifierImplEcBc(SecuritySignatureConfig<S> config, ECDSASigner signer) {

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
