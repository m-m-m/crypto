package net.sf.mmm.security.impl.sign;

import java.security.PrivateKey;
import java.security.PublicKey;

import net.sf.mmm.security.api.crypt.SecurityCryptor;
import net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorConfig;
import net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorFactory;
import net.sf.mmm.security.api.hash.SecurityHashCreator;
import net.sf.mmm.security.api.hash.SecurityHashFactory;
import net.sf.mmm.security.api.sign.SecuritySignatureFactory;
import net.sf.mmm.security.api.sign.SecuritySignatureSigner;
import net.sf.mmm.security.api.sign.SecuritySignatureVerifier;
import net.sf.mmm.security.impl.AbstractSecurityAlgorithm;
import net.sf.mmm.security.impl.crypt.asymmetric.SecurityAsymmetricCryptorFactoryImpl;

/**
 * Implementation of {@link SecuritySignatureFactory} combining a {@link SecurityCryptor} with a
 * {@link SecurityHashCreator}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecuritySignatureFactoryImplCryptorWithHash extends AbstractSecurityAlgorithm implements SecuritySignatureFactory {

  private final SecurityHashFactory hashFactory;

  private final SecurityAsymmetricCryptorFactory cryptorFactory;

  /**
   * The constructor.
   *
   * @param cryptorFactory the {@link SecurityAsymmetricCryptorFactory} to delegate to.
   * @param hashFactory the {@link SecurityHashFactory} to apply as extension.
   */
  public SecuritySignatureFactoryImplCryptorWithHash(SecurityAsymmetricCryptorFactory cryptorFactory, SecurityHashFactory hashFactory) {

    super();
    if (cryptorFactory instanceof SecurityAsymmetricCryptorFactoryImpl) {
      SecurityAsymmetricCryptorConfig config = ((SecurityAsymmetricCryptorFactoryImpl) cryptorFactory).getConfig();
      if (!config.isBidirectional()) {
        throw new IllegalStateException("Only bidirectional cryptor can be used for signature factory!");
      }
    }
    this.hashFactory = hashFactory;
    this.cryptorFactory = cryptorFactory;
  }

  @Override
  public String getAlgorithm() {

    return this.hashFactory.getAlgorithm() + "+" + this.cryptorFactory.getAlgorithm();
  }

  @Override
  public SecuritySignatureSigner newSigner(PrivateKey privateKey) {

    return new SecuritySignatureSignerImplWithHash(this.hashFactory.newHashCreator(), this.cryptorFactory.newEncryptorUnsafe(privateKey));
  }

  @Override
  public SecuritySignatureVerifier newVerifier(PublicKey publicKey) {

    return new SecuritySignatureVerifierImplCryptorWithHash(this.hashFactory.newHashCreator(),
        this.cryptorFactory.newDecryptorUnsafe(publicKey));
  }

}
