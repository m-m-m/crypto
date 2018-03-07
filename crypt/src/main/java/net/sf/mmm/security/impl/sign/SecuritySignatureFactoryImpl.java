package net.sf.mmm.security.impl.sign;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;

import net.sf.mmm.security.api.random.SecurityRandomFactory;
import net.sf.mmm.security.api.sign.SecuritySignatureConfig;
import net.sf.mmm.security.api.sign.SecuritySignatureFactory;
import net.sf.mmm.security.api.sign.SecuritySignatureSigner;
import net.sf.mmm.security.api.sign.SecuritySignatureVerifier;
import net.sf.mmm.security.impl.AbstractSecurityAlgorithmWithRandom;

/**
 * Default implementation of {@link SecuritySignatureFactory} based on {@link Signature}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecuritySignatureFactoryImpl extends AbstractSecurityAlgorithmWithRandom
    implements SecuritySignatureFactory {

  private final SecuritySignatureConfig config;

  /**
   * The constructor.
   *
   * @param config the {@link SecuritySignatureConfig}.
   * @param provider the security {@link Provider}.
   * @param randomFactory the {@link SecurityRandomFactory}.
   */
  public SecuritySignatureFactoryImpl(SecuritySignatureConfig config, Provider provider,
      SecurityRandomFactory randomFactory) {
    super(provider, randomFactory);
    this.config = config;
  }

  @Override
  public String getAlgorithm() {

    return this.config.getAlgorithm();
  }

  @Override
  public SecuritySignatureSigner newSigner(PrivateKey privateKey) {

    try {
      Signature signature = createSignature();
      signature.initSign(privateKey, createSecureRandom());
      return new SecuritySignatureSignerImpl(signature);
    } catch (Exception e) {
      throw creationFailedException(e, Signature.class);
    }
  }

  @Override
  public SecuritySignatureVerifier newVerifier(PublicKey publicKey) {

    try {
      Signature signature = createSignature();
      signature.initVerify(publicKey);
      return new SecuritySignatureVerifierImpl(signature);
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
