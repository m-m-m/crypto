package io.github.mmm.crypto.asymmetric.access.rsa;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import io.github.mmm.crypto.asymmetric.access.AsymmetricAccess;
import io.github.mmm.crypto.asymmetric.crypt.AsymmetricCryptorConfig;
import io.github.mmm.crypto.asymmetric.crypt.rsa.AsymmetricCryptorConfigRsa;
import io.github.mmm.crypto.asymmetric.key.rsa.AsymmetricKeyCreatorRsa;
import io.github.mmm.crypto.asymmetric.key.rsa.AsymmetricKeyPairRsa;
import io.github.mmm.crypto.asymmetric.sign.rsa.SignatureConfigRsa;
import io.github.mmm.crypto.asymmetric.sign.rsa.SignatureRsa;
import io.github.mmm.crypto.hash.HashConfig;
import io.github.mmm.crypto.provider.SecurityProvider;
import io.github.mmm.crypto.random.RandomFactory;

/// Direct builder for RSA (Ron Rivest, Adi Shamir and Leonard Adleman) used by PGP/GPG and many others. For details see
/// <a href="https://en.wikipedia.org/wiki/PKCS_1">PKCS #1</a>.
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public final class Rsa extends AsymmetricAccess<SignatureRsa, RSAPrivateKey, RSAPublicKey, AsymmetricKeyPairRsa, AsymmetricKeyCreatorRsa> {

  private final SecurityProvider provider;

  private final int keyLength;

  /// The constructor.
  ///
  /// @param signatureConfig the [SignatureConfigRsa].
  /// @param cryptorConfig the [AsymmetricCryptorConfig].
  /// @param randomFactory the optional [RandomFactory].
  /// @param keyLength the [key length][io.github.mmm.crypto.asymmetric.key.AsymmetricKeyCreator#getKeyLength()].
  /// @param provider the optional [SecurityProvider].
  private Rsa(SignatureConfigRsa signatureConfig, AsymmetricCryptorConfig<RSAPrivateKey, RSAPublicKey> cryptorConfig,
      RandomFactory randomFactory, int keyLength, SecurityProvider provider) {

    super(signatureConfig, cryptorConfig, randomFactory);
    this.keyLength = keyLength;
    this.provider = provider;
  }

  @Override
  public AsymmetricKeyCreatorRsa newKeyCreator() {

    return new AsymmetricKeyCreatorRsa(this.keyLength, this.provider, this.randomFactory);
  }

  /// @param hashAlgorithm the [algorithm][HashConfig#getAlgorithm()] for the hash used for signatures.
  /// @return a [Rsa] instance with a [key length][io.github.mmm.crypto.asymmetric.key.AsymmetricKeyCreator#getKeyLength()] of 4096 bits.
  public static Rsa of4096(String hashAlgorithm) {

    return of4096(new HashConfig(hashAlgorithm));
  }

  /// @param hashConfig the [HashConfig] for hashing data for [signatures][SignatureRsa].
  /// @return a [Rsa] instance with a [key length][io.github.mmm.crypto.asymmetric.key.AsymmetricKeyCreator#getKeyLength()] of 4096 bits.
  public static Rsa of4096(HashConfig hashConfig) {

    return of(4096, hashConfig);
  }

  /// @param keyLength the [key length][io.github.mmm.crypto.asymmetric.key.AsymmetricKeyCreator#getKeyLength()] in
  ///        bits.
  /// @param hashAlgorithm the [algorithm][HashConfig#getAlgorithm()] for the hash used for signatures.
  /// @return the according [Rsa] instance.
  public static Rsa of(int keyLength, String hashAlgorithm) {

    return of(keyLength, new HashConfig(hashAlgorithm));
  }

  /// @param keyLength the [key length][io.github.mmm.crypto.asymmetric.key.AsymmetricKeyCreator#getKeyLength()] in
  ///        bits.
  /// @param hashConfig the [HashConfig] for hashing data for [signatures][SignatureRsa].
  /// @return the according [Rsa] instance.
  public static Rsa of(int keyLength, HashConfig hashConfig) {

    return of(keyLength, hashConfig, hashConfig.getAlgorithm(), null, null);
  }

  /// @param keyLength the [key length][io.github.mmm.crypto.asymmetric.key.AsymmetricKeyCreator#getKeyLength()] in
  ///        bits.
  /// @param hashConfig the [HashConfig] for hashing data for [signatures][SignatureRsa].
  /// @param randomFactory the [RandomFactory].
  /// @return the according [Rsa] instance.
  public static Rsa of(int keyLength, HashConfig hashConfig, RandomFactory randomFactory) {

    return of(keyLength, hashConfig, hashConfig.getAlgorithm(), randomFactory, null);
  }

  /// @param keyLength the [key length][io.github.mmm.crypto.asymmetric.key.AsymmetricKeyCreator#getKeyLength()] in
  ///        bits.
  /// @param hashConfig the [HashConfig] for hashing data for [signatures][SignatureRsa].
  /// @param hashAlgorithm the [hash algorithm][HashConfig#getAlgorithm()] for the signature (e.g. for
  ///        HMac).
  /// @param randomFactory the [RandomFactory].
  /// @param provider the [SecurityProvider] to use.
  /// @return the according [Rsa] instance.
  public static Rsa of(int keyLength, HashConfig hashConfig, String hashAlgorithm, RandomFactory randomFactory,
      SecurityProvider provider) {

    SignatureConfigRsa signatureConfig = new SignatureConfigRsa(hashConfig, hashAlgorithm, provider);
    AsymmetricCryptorConfigRsa cryptorConfig = new AsymmetricCryptorConfigRsa(provider);
    return new Rsa(signatureConfig, cryptorConfig, randomFactory, keyLength, provider);
  }

}
