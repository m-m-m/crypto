package io.github.mmm.crypto.asymmetric.sign;

import java.security.PrivateKey;
import java.security.PublicKey;

import io.github.mmm.crypto.asymmetric.crypt.AsymmetricCryptorConfig;
import io.github.mmm.crypto.asymmetric.crypt.AsymmetricCryptorFactory;
import io.github.mmm.crypto.asymmetric.crypt.AsymmetricCryptorFactoryImpl;
import io.github.mmm.crypto.asymmetric.sign.generic.SignatureGeneric;
import io.github.mmm.crypto.crypt.Cryptor;
import io.github.mmm.crypto.hash.HashCreator;
import io.github.mmm.crypto.hash.HashFactory;

/**
 * Implementation of {@link SignatureProcessorFactory} combining a {@link Cryptor} with a
 * {@link HashCreator}.
 *
 * @param <PR> type of {@link PrivateKey}.
 * @param <PU> type of {@link PublicKey}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SignatureProcessorFactoryImplCryptorWithHash<PR extends PrivateKey, PU extends PublicKey>
    implements SignatureProcessorFactory<SignatureBinary, PR, PU> {

  private final HashFactory hashFactory;

  private final AsymmetricCryptorFactory<PR, PU> cryptorFactory;

  /**
   * The constructor.
   *
   * @param cryptorFactory the {@link AsymmetricCryptorFactory} to delegate to.
   * @param hashFactory the {@link HashFactory} to apply as extension.
   */
  public SignatureProcessorFactoryImplCryptorWithHash(AsymmetricCryptorFactory<PR, PU> cryptorFactory,
      HashFactory hashFactory) {

    super();
    if (cryptorFactory instanceof AsymmetricCryptorFactoryImpl) {
      AsymmetricCryptorConfig<PR, PU> config = ((AsymmetricCryptorFactoryImpl<PR, PU>) cryptorFactory).getConfig();
      if (!config.isBidirectional()) {
        throw new IllegalStateException("Only bidirectional cryptor can be used for signature factory!");
      }
    }
    this.hashFactory = hashFactory;
    this.cryptorFactory = cryptorFactory;
  }

  @Override
  public SignatureSigner<SignatureBinary> newSigner(PR privateKey) {

    return new SignatureSignerImplCryptorWithHash(this.hashFactory.newHashCreator(),
        this.cryptorFactory.newEncryptorUnsafe(privateKey));
  }

  @Override
  public SignatureVerifier<SignatureBinary> newVerifier(PU publicKey) {

    return new SignatureVerifierImplCryptorWithHash(this.hashFactory.newHashCreator(),
        this.cryptorFactory.newDecryptorUnsafe(publicKey));
  }

  @Override
  public SignatureBinary createSignature(byte[] data) {

    return new SignatureGeneric(data);
  }

  @Override
  public SignatureProcessorFactory<SignatureBinary, PR, PU> getSignatureFactoryWithoutHash() {

    throw new UnsupportedOperationException();
  }

  @Override
  public String toString() {

    return this.hashFactory.toString() + "+" + this.cryptorFactory.toString();
  }

}
