package net.sf.mmm.security.impl.sign;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;

import net.sf.mmm.security.api.hash.SecurityHashConfig;
import net.sf.mmm.security.api.hash.SecurityHashCreator;
import net.sf.mmm.security.api.random.SecurityRandomFactory;
import net.sf.mmm.security.api.sign.SecuritySignatureConfig;
import net.sf.mmm.security.api.sign.SecuritySignatureFactory;
import net.sf.mmm.security.api.sign.SecuritySignatureSigner;
import net.sf.mmm.security.api.sign.SecuritySignatureVerifier;
import net.sf.mmm.security.impl.AbstractSecurityAlgorithmWithRandom;
import net.sf.mmm.security.impl.hash.SecurityHashCreatorImplDigest;
import net.sf.mmm.security.impl.hash.SecurityHashCreatorImplMultipleRounds;

/**
 * Default implementation of {@link SecuritySignatureFactory} based on {@link Signature}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecuritySignatureFactoryImpl extends AbstractSecurityAlgorithmWithRandom implements SecuritySignatureFactory {

  private final SecuritySignatureConfig config;

  /**
   * The constructor.
   *
   * @param config the {@link SecuritySignatureConfig}.
   * @param provider the security {@link Provider}.
   * @param randomFactory the {@link SecurityRandomFactory}.
   */
  public SecuritySignatureFactoryImpl(SecuritySignatureConfig config, Provider provider, SecurityRandomFactory randomFactory) {

    super(provider, randomFactory);
    this.config = config;
  }

  @Override
  public String getAlgorithm() {

    return this.config.getAlgorithm();
  }

  private SecurityHashCreator newPreHashCreator() {

    SecurityHashConfig hashConfig = this.config.getHashConfig();
    if (hashConfig != null) {
      int preIterationCount = hashConfig.getIterationCount() - 1;
      if (preIterationCount > 0) {
        if (preIterationCount == 1) {
          return new SecurityHashCreatorImplDigest(hashConfig.getAlgorithm(), getProvider());
        } else {
          assert (preIterationCount > 1);
          return new SecurityHashCreatorImplMultipleRounds(hashConfig.getAlgorithm(), getProvider(), preIterationCount);
        }
      }
    }
    return null;
  }

  @Override
  public SecuritySignatureSigner newSigner(PrivateKey privateKey) {

    try {
      Signature signature = createSignature();
      signature.initSign(privateKey, createSecureRandom());
      SecuritySignatureSigner signer = new SecuritySignatureSignerImpl(signature);
      SecurityHashCreator hashGenerator = newPreHashCreator();
      if (hashGenerator != null) {
        signer = new SecuritySignatureSignerImplWithHash(hashGenerator, signer);
      }
      return signer;
    } catch (Exception e) {
      throw creationFailedException(e, Signature.class);
    }
  }

  @Override
  public SecuritySignatureVerifier newVerifier(PublicKey publicKey) {

    try {
      Signature signature = createSignature();
      signature.initVerify(publicKey);
      SecuritySignatureVerifier verifier = new SecuritySignatureVerifierImpl(signature);
      SecurityHashCreator hashGenerator = newPreHashCreator();
      if (hashGenerator != null) {
        verifier = new SecuritySignatureVerifierImplWithHash(hashGenerator, verifier);
      }
      return verifier;
    } catch (Exception e) {
      throw creationFailedException(e, Signature.class);
    }
  }

  private Signature createSignature() throws NoSuchAlgorithmException {

    Provider provider = getProvider();
    if (provider == null) {
      return Signature.getInstance(getAlgorithm());
    } else {
      return Signature.getInstance(getAlgorithm(), provider);
    }
  }

}
