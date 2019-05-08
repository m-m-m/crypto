package net.sf.mmm.security.api.asymmetric.sign;

import java.security.PrivateKey;
import java.security.PublicKey;

import net.sf.mmm.security.api.asymmetric.crypt.SecurityAsymmetricCryptorConfig;
import net.sf.mmm.security.api.asymmetric.crypt.SecurityAsymmetricCryptorFactory;
import net.sf.mmm.security.api.asymmetric.crypt.SecurityAsymmetricCryptorFactoryImpl;
import net.sf.mmm.security.api.asymmetric.sign.generic.SecuritySignatureGeneric;
import net.sf.mmm.security.api.crypt.SecurityCryptor;
import net.sf.mmm.security.api.hash.SecurityHashCreator;
import net.sf.mmm.security.api.hash.SecurityHashFactory;

/**
 * Implementation of {@link SecuritySignatureProcessorFactory} combining a {@link SecurityCryptor} with a
 * {@link SecurityHashCreator}.
 *
 * @param <PR> type of {@link PrivateKey}.
 * @param <PU> type of {@link PublicKey}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecuritySignatureProcessorFactoryImplCryptorWithHash<PR extends PrivateKey, PU extends PublicKey>
    implements SecuritySignatureProcessorFactory<SecuritySignature, PR, PU> {

  private final SecurityHashFactory hashFactory;

  private final SecurityAsymmetricCryptorFactory<PR, PU> cryptorFactory;

  /**
   * The constructor.
   *
   * @param cryptorFactory the {@link SecurityAsymmetricCryptorFactory} to delegate to.
   * @param hashFactory the {@link SecurityHashFactory} to apply as extension.
   */
  public SecuritySignatureProcessorFactoryImplCryptorWithHash(SecurityAsymmetricCryptorFactory<PR, PU> cryptorFactory,
      SecurityHashFactory hashFactory) {

    super();
    if (cryptorFactory instanceof SecurityAsymmetricCryptorFactoryImpl) {
      SecurityAsymmetricCryptorConfig<PR, PU> config = ((SecurityAsymmetricCryptorFactoryImpl<PR, PU>) cryptorFactory).getConfig();
      if (!config.isBidirectional()) {
        throw new IllegalStateException("Only bidirectional cryptor can be used for signature factory!");
      }
    }
    this.hashFactory = hashFactory;
    this.cryptorFactory = cryptorFactory;
  }

  @Override
  public SecuritySignatureSigner<SecuritySignature> newSigner(PR privateKey) {

    return new SecuritySignatureSignerImplCryptorWithHash(this.hashFactory.newHashCreator(),
        this.cryptorFactory.newEncryptorUnsafe(privateKey));
  }

  @Override
  public SecuritySignatureVerifier<SecuritySignature> newVerifier(PU publicKey) {

    return new SecuritySignatureVerifierImplCryptorWithHash(this.hashFactory.newHashCreator(),
        this.cryptorFactory.newDecryptorUnsafe(publicKey));
  }

  @Override
  public SecuritySignature createSignature(byte[] data) {

    return new SecuritySignatureGeneric(data);
  }

  @Override
  public String toString() {

    return this.hashFactory.toString() + "+" + this.cryptorFactory.toString();
  }

}
