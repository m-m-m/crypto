package net.sf.mmm.security.impl.sign;

import java.security.PrivateKey;
import java.security.PublicKey;

import net.sf.mmm.security.api.hash.SecurityHashCreator;
import net.sf.mmm.security.api.hash.SecurityHashFactory;
import net.sf.mmm.security.api.sign.SecuritySignatureCreator;
import net.sf.mmm.security.api.sign.SecuritySignatureFactory;
import net.sf.mmm.security.api.sign.SecuritySignatureSigner;
import net.sf.mmm.security.api.sign.SecuritySignatureVerifier;
import net.sf.mmm.security.impl.AbstractSecurityAlgorithm;

/**
 * Implementation of {@link SecuritySignatureFactory} combining a {@link SecuritySignatureCreator} with a
 * {@link SecurityHashCreator}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecuritySignatureFactoryImplWithHash extends AbstractSecurityAlgorithm
    implements SecuritySignatureFactory {

  private final SecuritySignatureFactory signatureFactory;

  private final SecurityHashFactory hashFactory;

  /**
   * The constructor.
   *
   * @param signatureFactory the {@link SecuritySignatureFactory} to delegate to.
   * @param hashFactory the {@link SecurityHashFactory} to apply as extension.
   */
  public SecuritySignatureFactoryImplWithHash(SecuritySignatureFactory signatureFactory,
      SecurityHashFactory hashFactory) {
    super();
    this.signatureFactory = signatureFactory;
    this.hashFactory = hashFactory;
  }

  @Override
  public String getAlgorithm() {

    return this.hashFactory.getAlgorithm() + "+" + this.signatureFactory.getAlgorithm();
  }

  @Override
  public SecuritySignatureSigner newSigner(PrivateKey privateKey) {

    return new SecuritySignatureSignerImplWithHash(this.hashFactory.newHashCreator(),
        this.signatureFactory.newSigner(privateKey));
  }

  @Override
  public SecuritySignatureVerifier newVerifier(PublicKey publicKey) {

    return new SecuritySignatureVerifierImplWithHash(this.hashFactory.newHashCreator(),
        this.signatureFactory.newVerifier(publicKey));
  }

}
