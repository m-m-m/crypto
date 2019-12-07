package io.github.mmm.crypto.asymmetric.sign.ec.bc;

import java.math.BigInteger;

import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;

import io.github.mmm.crypto.asymmetric.sign.SignatureBinary;
import io.github.mmm.crypto.asymmetric.sign.SignatureSigner;
import io.github.mmm.crypto.asymmetric.sign.ec.SignatureConfigEcDsa;

/**
 * Implementation of {@link SignatureSigner} for {@link SignatureEcBc}.
 *
 * @param <S> type of {@link SignatureBinary}.
 * @since 1.0.0
 */
public class SignatureSignerImplEcBc<S extends SignatureEcBc> extends SignatureProcessorImplEcBc<S>
    implements SignatureSigner<S> {

  private final BCECPublicKey publicKey;

  /**
   * The constructor.
   *
   * @param config the {@link #getConfig() config}.
   * @param signer the underlying {@link ECDSASigner}.
   * @param publicKey the {@link #getPublicKey() public key}.
   */
  public SignatureSignerImplEcBc(SignatureConfigEcDsa<S> config, ECDSASigner signer, BCECPublicKey publicKey) {

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
