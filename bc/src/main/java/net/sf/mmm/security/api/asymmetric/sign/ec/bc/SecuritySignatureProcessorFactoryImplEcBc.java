package net.sf.mmm.security.api.asymmetric.sign.ec.bc;

import java.security.Signature;

import net.sf.mmm.security.api.algorithm.AbstractSecurityAlgorithm;
import net.sf.mmm.security.api.asymmetric.key.ec.bc.SecurityAsymmetricKeyPairEcBc;
import net.sf.mmm.security.api.asymmetric.sign.SecuritySignature;
import net.sf.mmm.security.api.asymmetric.sign.SecuritySignatureConfig;
import net.sf.mmm.security.api.asymmetric.sign.SecuritySignatureProcessorFactory;
import net.sf.mmm.security.api.asymmetric.sign.SecuritySignatureSigner;
import net.sf.mmm.security.api.asymmetric.sign.SecuritySignatureSignerImplWithHash;
import net.sf.mmm.security.api.asymmetric.sign.SecuritySignatureVerifier;
import net.sf.mmm.security.api.asymmetric.sign.SecuritySignatureVerifierImplWithHash;
import net.sf.mmm.security.api.asymmetric.sign.ec.SecuritySignatureConfigEcDsa;
import net.sf.mmm.security.api.hash.SecurityHashConfig;
import net.sf.mmm.security.api.hash.SecurityHashCreator;
import net.sf.mmm.security.api.hash.SecurityHashCreatorImplDigest;
import net.sf.mmm.security.api.hash.SecurityHashCreatorImplMultipleRounds;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jcajce.provider.util.DigestFactory;

/**
 * Default implementation of {@link SecuritySignatureProcessorFactory} for {@link SecuritySignatureEcBc}.
 *
 * @param <S> type of {@link SecuritySignature}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecuritySignatureProcessorFactoryImplEcBc<S extends SecuritySignatureEcBc> extends AbstractSecurityAlgorithm
    implements SecuritySignatureProcessorFactory<S, BCECPrivateKey, BCECPublicKey> {

  private final SecuritySignatureConfigEcDsa<S> config;

  /**
   * The constructor.
   *
   * @param config the {@link SecuritySignatureConfig}.
   */
  public SecuritySignatureProcessorFactoryImplEcBc(SecuritySignatureConfigEcDsa<S> config) {

    super();
    this.config = config;
  }

  @Override
  public String getAlgorithm() {

    return this.config.getAlgorithm();
  }

  private SecurityHashCreator newPreHashCreator() {

    SecurityHashConfig hashConfig = this.config.getHashConfig();
    if (hashConfig != null) {
      int iterationCount = hashConfig.getIterationCount();
      if (iterationCount == 1) {
        return new SecurityHashCreatorImplDigest(hashConfig.getAlgorithm(), null);
      } else if (iterationCount > 1) {
        return new SecurityHashCreatorImplMultipleRounds(hashConfig.getAlgorithm(), null, iterationCount);
      }
    }
    return null;
  }

  @Override
  public SecuritySignatureSigner<S> newSigner(BCECPrivateKey privateKey) {

    try {
      Digest digest = createDigest(this.config.getSignatureAlgorithm().getHashAlgorithm());
      ECDSASigner ecSigner = new ECDSASigner(new HMacDSAKCalculator(digest));
      AsymmetricKeyParameter privKeyParams = ECUtil.generatePrivateKeyParameter(privateKey);
      ecSigner.init(true, privKeyParams);
      BCECPublicKey publicKey = SecurityAsymmetricKeyPairEcBc.createPublicKey(privateKey);
      SecuritySignatureSigner<S> signer = new SecuritySignatureSignerImplEcBc<>(this.config, ecSigner, publicKey);
      SecurityHashCreator hashGenerator = newPreHashCreator();
      if (hashGenerator != null) {
        signer = new SecuritySignatureSignerImplWithHash<>(hashGenerator, signer);
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
  public SecuritySignatureVerifier<S> newVerifier(BCECPublicKey publicKey) {

    try {
      ECDSASigner signer = new ECDSASigner();
      AsymmetricKeyParameter publicKeyParameters = ECUtil.generatePublicKeyParameter(publicKey);
      signer.init(false, publicKeyParameters);
      SecuritySignatureVerifier<S> verifier = new SecuritySignatureVerifierImplEcBc<>(this.config, signer);
      SecurityHashCreator hashGenerator = newPreHashCreator();
      if (hashGenerator != null) {
        verifier = new SecuritySignatureVerifierImplWithHash<>(hashGenerator, verifier);
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
  public SecuritySignatureProcessorFactory<S, BCECPrivateKey, BCECPublicKey> getSignatureFactoryWithoutHash() {

    if (this.config.getHashConfig() == null) {
      return this;
    }
    return new SecuritySignatureProcessorFactoryImplEcBc<>(this.config.withoutHashConfig());
  }

}
