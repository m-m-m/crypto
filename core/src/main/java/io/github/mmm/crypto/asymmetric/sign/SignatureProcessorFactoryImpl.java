package io.github.mmm.crypto.asymmetric.sign;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import io.github.mmm.crypto.algorithm.AbstractCryptoAlgorithmWithRandom;
import io.github.mmm.crypto.hash.HashConfig;
import io.github.mmm.crypto.hash.HashCreator;
import io.github.mmm.crypto.hash.HashCreatorImplDigest;
import io.github.mmm.crypto.hash.HashCreatorImplMultipleRounds;
import io.github.mmm.crypto.random.RandomFactory;

/**
 * Default implementation of {@link SignatureProcessorFactory} based on {@link Signature}.
 *
 * @param <S> type of {@link SignatureBinary}.
 * @param <PR> type of {@link PrivateKey}.
 * @param <PU> type of {@link PublicKey}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SignatureProcessorFactoryImpl<S extends SignatureBinary, PR extends PrivateKey, PU extends PublicKey>
    extends AbstractCryptoAlgorithmWithRandom implements SignatureProcessorFactory<S, PR, PU> {

  private final SignatureConfig<S> config;

  /**
   * The constructor.
   *
   * @param config the {@link SignatureConfig}.
   * @param randomFactory the {@link RandomFactory}.
   */
  public SignatureProcessorFactoryImpl(SignatureConfig<S> config, RandomFactory randomFactory) {

    super(config.getProvider(), randomFactory);
    this.config = config;
  }

  @Override
  public String getAlgorithm() {

    return this.config.getAlgorithm();
  }

  private HashCreator newHashCreator() {

    HashConfig hashConfig = this.config.getHashConfig();
    if (hashConfig != null) {
      String algorithm = hashConfig.getAlgorithm();
      if (HashConfig.ALGORITHM_NONE.equals(algorithm)) {
        return null;
      }
      int iterationCount = hashConfig.getIterationCount();
      if (iterationCount == 1) {
        return new HashCreatorImplDigest(algorithm, getProvider());
      } else {
        assert (iterationCount > 1);
        return new HashCreatorImplMultipleRounds(algorithm, getProvider(), iterationCount);
      }
    }
    return null;
  }

  @Override
  public SignatureSigner<S> newSigner(PR privateKey) {

    try {
      Signature signature = getProvider().createSignature(this.config.getAlgorithm());
      signature.initSign(privateKey, createSecureRandom());
      SignatureSigner<S> signer = new SignatureSignerImpl<>(signature, this.config.getSignatureFactory());
      HashCreator hashGenerator = newHashCreator();
      if (hashGenerator != null) {
        signer = new SignatureSignerImplWithHash<>(hashGenerator, signer);
      }
      return signer;
    } catch (Exception e) {
      throw creationFailedException(e, Signature.class);
    }
  }

  @Override
  public SignatureVerifier<S> newVerifier(PU publicKey) {

    try {
      Signature signature = getProvider().createSignature(this.config.getAlgorithm());
      signature.initVerify(publicKey);
      SignatureVerifier<S> verifier = new SignatureVerifierImpl<>(signature);
      HashCreator hashGenerator = newHashCreator();
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
  public SignatureProcessorFactory<S, PR, PU> getSignatureFactoryWithoutHash() {

    if (this.config.getHashConfig() == null) {
      return this;
    }
    return new SignatureProcessorFactoryImpl<>(this.config.withoutHashConfig(), getRandomFactory());
  }

}
