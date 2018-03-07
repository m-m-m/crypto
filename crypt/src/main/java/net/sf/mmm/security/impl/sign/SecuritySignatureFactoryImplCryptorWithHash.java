package net.sf.mmm.security.impl.sign;

import java.security.PrivateKey;
import java.security.PublicKey;

import net.sf.mmm.security.api.crypt.SecurityCryptor;
import net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorFactoryPrivatePublic;
import net.sf.mmm.security.api.hash.SecurityHashCreator;
import net.sf.mmm.security.api.hash.SecurityHashFactory;
import net.sf.mmm.security.api.sign.SecuritySignatureFactory;
import net.sf.mmm.security.api.sign.SecuritySignatureSigner;
import net.sf.mmm.security.api.sign.SecuritySignatureVerifier;
import net.sf.mmm.security.impl.AbstractSecurityAlgorithm;

/**
 * Implementation of {@link SecuritySignatureFactory} combining a {@link SecurityCryptor} with a
 * {@link SecurityHashCreator}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecuritySignatureFactoryImplCryptorWithHash extends AbstractSecurityAlgorithm
    implements SecuritySignatureFactory {

  private final SecurityHashFactory hashFactory;

  private final SecurityAsymmetricCryptorFactoryPrivatePublic cryptorFactory;

  /**
   * The constructor.
   *
   * @param cryptorFactory the {@link SecurityAsymmetricCryptorFactoryPrivatePublic} to delegate to.
   * @param hashFactory the {@link SecurityHashFactory} to apply as extension.
   */
  public SecuritySignatureFactoryImplCryptorWithHash(SecurityAsymmetricCryptorFactoryPrivatePublic cryptorFactory,
      SecurityHashFactory hashFactory) {

    super();
    this.hashFactory = hashFactory;
    this.cryptorFactory = cryptorFactory;
  }

  @Override
  public String getAlgorithm() {

    return this.hashFactory.getAlgorithm() + "+" + this.cryptorFactory.getAlgorithm();
  }

  @Override
  public SecuritySignatureSigner newSigner(PrivateKey privateKey) {

    return new SecuritySignatureSignerImplWithHash(this.hashFactory.newHashCreator(),
        this.cryptorFactory.newEncryptor(privateKey));
  }

  @Override
  public SecuritySignatureVerifier newVerifier(PublicKey publicKey) {

    return new SecuritySignatureVerifierImplCryptorWithHash(this.hashFactory.newHashCreator(),
        this.cryptorFactory.newDecryptor(publicKey));
  }

}
