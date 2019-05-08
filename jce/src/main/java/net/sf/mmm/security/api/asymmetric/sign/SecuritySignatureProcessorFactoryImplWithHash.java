package net.sf.mmm.security.api.asymmetric.sign;

import java.security.PrivateKey;
import java.security.PublicKey;

import net.sf.mmm.security.api.hash.SecurityHashCreator;
import net.sf.mmm.security.api.hash.SecurityHashFactory;

/**
 * Implementation of {@link SecuritySignatureProcessorFactory} combining a {@link SecuritySignatureProcessor} with a
 * {@link SecurityHashCreator}.
 *
 * @param <S> type of {@link SecuritySignature}.
 * @param <PR> type of {@link PrivateKey}.
 * @param <PU> type of {@link PublicKey}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecuritySignatureProcessorFactoryImplWithHash<S extends SecuritySignature, PR extends PrivateKey, PU extends PublicKey>
    implements SecuritySignatureProcessorFactory<S, PR, PU> {

  private final SecuritySignatureProcessorFactory<S, PR, PU> signatureFactory;

  private final SecurityHashFactory hashFactory;

  /**
   * The constructor.
   *
   * @param signatureFactory the {@link SecuritySignatureProcessorFactory} to delegate to.
   * @param hashFactory the {@link SecurityHashFactory} to apply before signing or verifying.
   */
  public SecuritySignatureProcessorFactoryImplWithHash(SecuritySignatureProcessorFactory<S, PR, PU> signatureFactory,
      SecurityHashFactory hashFactory) {

    super();
    this.signatureFactory = signatureFactory;
    this.hashFactory = hashFactory;
  }

  @Override
  public SecuritySignatureSigner<S> newSigner(PR privateKey) {

    return new SecuritySignatureSignerImplWithHash<>(this.hashFactory.newHashCreator(), this.signatureFactory.newSigner(privateKey));
  }

  @Override
  public SecuritySignatureVerifier<S> newVerifier(PU publicKey) {

    return new SecuritySignatureVerifierImplWithHash<>(this.hashFactory.newHashCreator(), this.signatureFactory.newVerifier(publicKey));
  }

  @Override
  public S createSignature(byte[] data) {

    return this.signatureFactory.createSignature(data);
  }

  @Override
  public String toString() {

    return this.hashFactory.toString() + "+" + this.signatureFactory.toString();
  }

}
