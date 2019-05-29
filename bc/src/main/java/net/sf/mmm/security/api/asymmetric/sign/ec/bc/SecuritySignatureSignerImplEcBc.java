package net.sf.mmm.security.api.asymmetric.sign.ec.bc;

import java.math.BigInteger;

import net.sf.mmm.security.api.asymmetric.sign.SecuritySignature;
import net.sf.mmm.security.api.asymmetric.sign.SecuritySignatureSigner;
import net.sf.mmm.security.api.asymmetric.sign.ec.SecuritySignatureConfigEcDsa;

import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;

/**
 * Implementation of {@link SecuritySignatureSigner}.
 *
 * @param <S> type of {@link SecuritySignature}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecuritySignatureSignerImplEcBc<S extends SecuritySignatureEcBc> extends SecuritySignatureProcessorImplEcBc<S>
    implements SecuritySignatureSigner<S> {

  private final BCECPublicKey publicKey;

  /**
   * The constructor.
   *
   * @param config the {@link #getConfig() config}.
   * @param signer the underlying {@link ECDSASigner}.
   * @param publicKey the {@link #getPublicKey() public key}.
   */
  public SecuritySignatureSignerImplEcBc(SecuritySignatureConfigEcDsa<S> config, ECDSASigner signer, BCECPublicKey publicKey) {

    super(config, signer);
    this.publicKey = publicKey;
  }

  /**
   * @return the {@link BCECPublicKey}.
   */
  protected BCECPublicKey getPublicKey() {

    return this.publicKey;
  }

  @Override
  public S signAfterUpdate(boolean reset) {

    if (this.data == null) {
      throw new IllegalStateException("No data was specified to sign!");
    }
    BigInteger[] signatureNums = this.signer.generateSignature(this.data);
    S signature = getSignatureFactory().create(signatureNums[0], signatureNums[1], this.data, this.publicKey);
    this.data = null;
    return signature;
  }

  @Override
  public byte[] signAfterUpdateRaw(boolean reset) {

    return signAfterUpdate(reset).getData();
  }

}
