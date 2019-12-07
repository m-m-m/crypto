package io.github.mmm.crypto.asymmetric.sign.ec.bc;

import java.security.Signature;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jcajce.provider.util.DigestFactory;

import io.github.mmm.crypto.algorithm.AbstractSecurityAlgorithm;
import io.github.mmm.crypto.asymmetric.key.ec.bc.AsymmetricKeyPairEcBc;
import io.github.mmm.crypto.asymmetric.sign.SignatureBinary;
import io.github.mmm.crypto.asymmetric.sign.SignatureConfig;
import io.github.mmm.crypto.asymmetric.sign.SignatureProcessorFactory;
import io.github.mmm.crypto.asymmetric.sign.SignatureSigner;
import io.github.mmm.crypto.asymmetric.sign.SignatureSignerImplWithHash;
import io.github.mmm.crypto.asymmetric.sign.SignatureVerifier;
import io.github.mmm.crypto.asymmetric.sign.SignatureVerifierImplWithHash;
import io.github.mmm.crypto.asymmetric.sign.ec.SignatureConfigEcDsa;
import io.github.mmm.crypto.hash.HashConfig;
import io.github.mmm.crypto.hash.HashCreator;
import io.github.mmm.crypto.hash.HashCreatorImplDigest;
import io.github.mmm.crypto.hash.HashCreatorImplMultipleRounds;

/**
 * Default implementation of {@link SignatureProcessorFactory} for {@link SignatureEcBc}.
 *
 * @param <S> type of {@link SignatureBinary}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SignatureProcessorFactoryImplEcBc<S extends SignatureEcBc> extends AbstractSecurityAlgorithm
    implements SignatureProcessorFactory<S, BCECPrivateKey, BCECPublicKey> {

  private final SignatureConfigEcDsa<S> config;

  /**
   * The constructor.
   *
   * @param config the {@link SignatureConfig}.
   */
  public SignatureProcessorFactoryImplEcBc(SignatureConfigEcDsa<S> config) {

    super();
    this.config = config;
  }

  @Override
  public String getAlgorithm() {

    return this.config.getAlgorithm();
  }

  private HashCreator newPreHashCreator() {

    HashConfig hashConfig = this.config.getHashConfig();
    if (hashConfig != null) {
      int iterationCount = hashConfig.getIterationCount();
      if (iterationCount == 1) {
        return new HashCreatorImplDigest(hashConfig.getAlgorithm(), null);
      } else if (iterationCount > 1) {
        return new HashCreatorImplMultipleRounds(hashConfig.getAlgorithm(), null, iterationCount);
      }
    }
    return null;
  }

  @Override
  public SignatureSigner<S> newSigner(BCECPrivateKey privateKey) {

    try {
      Digest digest = createDigest(this.config.getSignatureAlgorithm().getHashAlgorithm());
      ECDSASigner ecSigner = new ECDSASigner(new HMacDSAKCalculator(digest));
      AsymmetricKeyParameter privKeyParams = ECUtil.generatePrivateKeyParameter(privateKey);
      ecSigner.init(true, privKeyParams);
      BCECPublicKey publicKey = AsymmetricKeyPairEcBc.createPublicKey(privateKey);
      SignatureSigner<S> signer = new SignatureSignerImplEcBc<>(this.config, ecSigner, publicKey);
      HashCreator hashGenerator = newPreHashCreator();
      if (hashGenerator != null) {
        signer = new SignatureSignerImplWithHash<>(hashGenerator, signer);
      }
      return signer;
    } catch (Exception e) {
      throw creationFailedException(e, Signature.class);
    }
  }

  private static Digest createDigest(String algorithm) {

    Digest digest = DigestFactory.getDigest(algorithm);
    if (digest == null) {
      throw new IllegalArgumentException(algorithm);
    }
    return digest;
  }

  @Override
  public SignatureVerifier<S> newVerifier(BCECPublicKey publicKey) {

    try {
      ECDSASigner signer = new ECDSASigner();
      AsymmetricKeyParameter publicKeyParameters = ECUtil.generatePublicKeyParameter(publicKey);
      signer.init(false, publicKeyParameters);
      SignatureVerifier<S> verifier = new SignatureVerifierImplEcBc<>(this.config, signer);
      HashCreator hashGenerator = newPreHashCreator();
      if (hashGenerator != null) {
        verifier = new SignatureVerifierImplWithHash<>(hashGenerator, verifier);
      }
      return verifier;
    } catch (Exception e) {
      throw creationFailedException(e, Signature.class);
    }
  }

  @Override
  public S createSignature(byte[] data) {

    return this.config.getSignatureFactory().createSignature(data);
  }

  @Override
  public SignatureProcessorFactory<S, BCECPrivateKey, BCECPublicKey> getSignatureFactoryWithoutHash() {

    if (this.config.getHashConfig() == null) {
      return this;
    }
    return new SignatureProcessorFactoryImplEcBc<>(this.config.withoutHashConfig());
  }

}
