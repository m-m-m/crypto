package net.sf.mmm.security.api.asymmetric.sign;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import net.sf.mmm.security.api.AbstractSecurityAlgorithmWithRandom;
import net.sf.mmm.security.api.hash.SecurityHashConfig;
import net.sf.mmm.security.api.hash.SecurityHashCreator;
import net.sf.mmm.security.api.hash.SecurityHashCreatorImplDigest;
import net.sf.mmm.security.api.hash.SecurityHashCreatorImplMultipleRounds;
import net.sf.mmm.security.api.random.SecurityRandomFactory;

/**
 * Default implementation of {@link SecuritySignatureProcessorFactory} based on {@link Signature}.
 *
 * @param <S> type of {@link SecuritySignature}.
 * @param <PR> type of {@link PrivateKey}.
 * @param <PU> type of {@link PublicKey}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecuritySignatureProcessorFactoryImpl<S extends SecuritySignature, PR extends PrivateKey, PU extends PublicKey>
    extends AbstractSecurityAlgorithmWithRandom implements SecuritySignatureProcessorFactory<S, PR, PU> {

  private final SecuritySignatureConfig<S> config;

  /**
   * The constructor.
   *
   * @param config the {@link SecuritySignatureConfig}.
   * @param randomFactory the {@link SecurityRandomFactory}.
   */
  public SecuritySignatureProcessorFactoryImpl(SecuritySignatureConfig<S> config, SecurityRandomFactory randomFactory) {

    super(config.getProvider(), randomFactory);
    this.config = config;
  }

  @Override
  public String getAlgorithm() {

    return this.config.getAlgorithm();
  }

  private SecurityHashCreator newHashCreator() {

    SecurityHashConfig hashConfig = this.config.getHashConfig();
    if (hashConfig != null) {
      String algorithm = hashConfig.getAlgorithm();
      if (SecurityHashConfig.ALGORITHM_NONE.equals(algorithm)) {
        return null;
      }
      int iterationCount = hashConfig.getIterationCount();
      if (iterationCount == 1) {
        return new SecurityHashCreatorImplDigest(algorithm, getProvider());
      } else {
        assert (iterationCount > 1);
        return new SecurityHashCreatorImplMultipleRounds(algorithm, getProvider(), iterationCount);
      }
    }
    return null;
  }

  @Override
  public SecuritySignatureSigner<S> newSigner(PR privateKey) {

    try {
      Signature signature = getProvider().createSignature(this.config.getAlgorithm());
      signature.initSign(privateKey, createSecureRandom());
      SecuritySignatureSigner<S> signer = new SecuritySignatureSignerImpl<>(signature, this.config.getSignatureFactory());
      SecurityHashCreator hashGenerator = newHashCreator();
      if (hashGenerator != null) {
        signer = new SecuritySignatureSignerImplWithHash<>(hashGenerator, signer);
      }
      return signer;
    } catch (Exception e) {
      throw creationFailedException(e, Signature.class);
    }
  }

  @Override
  public SecuritySignatureVerifier<S> newVerifier(PU publicKey) {

    try {
      Signature signature = getProvider().createSignature(this.config.getAlgorithm());
      signature.initVerify(publicKey);
      SecuritySignatureVerifier<S> verifier = new SecuritySignatureVerifierImpl<>(signature);
      SecurityHashCreator hashGenerator = newHashCreator();
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
  public SecuritySignatureProcessorFactory<S, PR, PU> getSignatureFactoryWithoutHash() {

    if (this.config.getHashConfig() == null) {
      return this;
    }
    return new SecuritySignatureProcessorFactoryImpl<>(this.config.withoutHashConfig(), getRandomFactory());
  }

}
