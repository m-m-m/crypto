package net.sf.mmm.security.api.asymmetric.access;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

import net.sf.mmm.security.api.SecurityAccess;
import net.sf.mmm.security.api.asymmetric.crypt.SecurityAsymmetricCryptorConfig;
import net.sf.mmm.security.api.asymmetric.crypt.SecurityAsymmetricCryptorFactory;
import net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyCreator;
import net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyFactory;
import net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyPair;
import net.sf.mmm.security.api.asymmetric.sign.SecuritySignature;
import net.sf.mmm.security.api.asymmetric.sign.SecuritySignatureConfig;
import net.sf.mmm.security.api.asymmetric.sign.SecuritySignatureProcessorFactory;
import net.sf.mmm.security.api.asymmetric.sign.SecuritySignatureProcessorFactoryImpl;
import net.sf.mmm.security.api.asymmetric.sign.SecuritySignatureSigner;
import net.sf.mmm.security.api.asymmetric.sign.SecuritySignatureVerifier;
import net.sf.mmm.security.api.crypt.SecurityDecryptor;
import net.sf.mmm.security.api.crypt.SecurityDecryptorImplCipher;
import net.sf.mmm.security.api.crypt.SecurityEncryptor;
import net.sf.mmm.security.api.crypt.SecurityEncryptorImplCiper;
import net.sf.mmm.security.api.hash.SecurityHashCreator;
import net.sf.mmm.security.api.hash.SecurityHashFactory;
import net.sf.mmm.security.api.hash.access.SecurityAccessHash;
import net.sf.mmm.security.api.random.SecurityRandomFactory;

/**
 * Abstract base implementation of factory for {@link SecurityAsymmetricKeyCreator key management},
 * {@link SecurityAsymmetricCryptorFactory encryption/decryption}, and {@link SecuritySignatureProcessorFactory
 * signature management} based on {@link net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyPair asymmetric}
 * cryptography.
 *
 * @param <S> type of {@link SecuritySignature}.
 * @param <PR> type of {@link PrivateKey}.
 * @param <PU> type of {@link PublicKey}.
 * @param <PAIR> type of {@link SecurityAsymmetricKeyPair}.
 * @param <KC> type of {@link SecurityAsymmetricKeyCreator}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class SecurityAccessAsymmetric<S extends SecuritySignature, PR extends PrivateKey, PU extends PublicKey, PAIR extends SecurityAsymmetricKeyPair<PR, PU>, KC extends SecurityAsymmetricKeyCreator<PR, PU, PAIR>>
    extends SecurityAccess implements SecurityAsymmetricKeyFactory<KC>, SecurityAsymmetricCryptorFactory<PR, PU>,
    SecuritySignatureProcessorFactory<S, PR, PU>, SecurityHashFactory {

  /** The {@link SecurityAsymmetricCryptorConfig}. */
  protected final SecurityAsymmetricCryptorConfig<PR, PU> cryptorConfig;

  private final SecuritySignatureConfig<S> signatureConfig;

  /** The {@link SecurityRandomFactory}. */
  protected final SecurityRandomFactory randomFactory;

  private final SecuritySignatureProcessorFactory<S, PR, PU> signatureFactory;

  private final SecurityAccessHash hashFactory;

  private KC keyCreator;

  /**
   * The constructor.
   *
   * @param signatureConfig the {@link SecuritySignatureConfig}.
   * @param cryptorConfig the {@link SecurityAsymmetricCryptorConfig}.
   * @param randomFactory the {@link SecurityRandomFactory}.
   */
  public SecurityAccessAsymmetric(SecuritySignatureConfig<S> signatureConfig, SecurityAsymmetricCryptorConfig<PR, PU> cryptorConfig,
      SecurityRandomFactory randomFactory) {

    this(signatureConfig, null, cryptorConfig, randomFactory);
  }

  /**
   * The constructor.
   *
   * @param signatureConfig the {@link SecuritySignatureConfig}.
   * @param signatureFactory the {@link SecuritySignatureProcessorFactory}.
   * @param cryptorConfig the {@link SecurityAsymmetricCryptorConfig}.
   * @param randomFactory the {@link SecurityRandomFactory}.
   */
  public SecurityAccessAsymmetric(SecuritySignatureConfig<S> signatureConfig, SecuritySignatureProcessorFactory<S, PR, PU> signatureFactory,
      SecurityAsymmetricCryptorConfig<PR, PU> cryptorConfig, SecurityRandomFactory randomFactory) {

    super();
    this.signatureConfig = signatureConfig;
    if (signatureFactory == null) {
      this.signatureFactory = new SecuritySignatureProcessorFactoryImpl<>(signatureConfig, randomFactory);
    } else {
      this.signatureFactory = signatureFactory;
    }
    this.cryptorConfig = cryptorConfig;
    this.randomFactory = randomFactory;
    this.hashFactory = new SecurityAccessHash(signatureConfig.getHashConfig());
  }

  /**
   * @return the {@link SecuritySignatureConfig}.
   */
  public SecuritySignatureConfig<S> getSignatureConfig() {

    return this.signatureConfig;
  }

  /**
   * @return the {@link SecurityAsymmetricCryptorConfig}.
   */
  public SecurityAsymmetricCryptorConfig<PR, PU> getCryptorConfig() {

    return this.cryptorConfig;
  }

  private KC getKeyCreatorInternal() {

    if (this.keyCreator == null) {
      this.keyCreator = newKeyCreator();
    }
    return this.keyCreator;
  }

  @Override
  public SecurityDecryptor newDecryptorUnsafe(Key decryptionKey) {

    return new SecurityDecryptorImplCipher(this.randomFactory, this.cryptorConfig, decryptionKey);
  }

  @Override
  public SecurityDecryptor newDecryptor(PR privateKey) {

    getKeyCreatorInternal().verifyKey(privateKey);
    return newDecryptorUnsafe(privateKey);
  }

  @Override
  public SecurityEncryptor newEncryptorUnsafe(Key encryptionKey) {

    return new SecurityEncryptorImplCiper(this.randomFactory, this.cryptorConfig, encryptionKey);
  }

  @Override
  public SecurityEncryptor newEncryptor(PU publicKey) {

    getKeyCreatorInternal().verifyKey(publicKey);
    return newEncryptorUnsafe(publicKey);
  }

  @Override
  public SecuritySignatureSigner<S> newSigner(PR privateKey) {

    getKeyCreatorInternal().verifyKey(privateKey);
    return this.signatureFactory.newSigner(privateKey);
  }

  @Override
  public SecuritySignatureVerifier<S> newVerifier(PU publicKey) {

    getKeyCreatorInternal().verifyKey(publicKey);
    return this.signatureFactory.newVerifier(publicKey);
  }

  @Override
  public S createSignature(byte[] data) {

    return this.signatureFactory.createSignature(data);
  }

  @Override
  public SecurityHashCreator newHashCreator() {

    return this.hashFactory.newHashCreator();
  }

  @Override
  public SecuritySignatureProcessorFactory<S, PR, PU> getSignatureFactoryWithoutHash() {

    return this.signatureFactory.getSignatureFactoryWithoutHash();
  }

}
