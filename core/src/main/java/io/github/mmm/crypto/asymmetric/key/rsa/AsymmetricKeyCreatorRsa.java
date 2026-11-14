package io.github.mmm.crypto.asymmetric.key.rsa;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;

import io.github.mmm.crypto.asymmetric.key.AbstractAsymmetricKeyCreator;
import io.github.mmm.crypto.asymmetric.key.AsymmetricKeyCreator;
import io.github.mmm.crypto.provider.SecurityProvider;
import io.github.mmm.crypto.random.RandomFactory;

/// Implementation of [AsymmetricKeyCreator] for [RSA][AsymmetricKeyPairRsa].
///
/// @since 1.0.0
public class AsymmetricKeyCreatorRsa
    extends AbstractAsymmetricKeyCreator<RSAPrivateKey, RSAPublicKey, AsymmetricKeyPairRsa> {

  /// The constructor.
  ///
  /// @param keyLength the [key length][#getKeyLength()].
  public AsymmetricKeyCreatorRsa(int keyLength) {

    this(keyLength, null, null);
  }

  /// The constructor.
  ///
  /// @param keyLength the [key length][#getKeyLength()].
  /// @param provider the [provider][#getProvider()].
  /// @param randomFactory the [random factory][#getRandomFactory()].
  public AsymmetricKeyCreatorRsa(int keyLength, SecurityProvider provider, RandomFactory randomFactory) {

    super(AsymmetricKeyPairRsa.getKeyFactory(), keyLength, provider, randomFactory);
    register(new AsymmetricKeyPairFactoryRsaCompact());
  }

  @Override
  public AsymmetricKeyPairRsa createKeyPair(RSAPrivateKey privateKey, RSAPublicKey publicKey) {

    return new AsymmetricKeyPairRsa(privateKey, publicKey);
  }

  @Override
  public int getKeyLength(RSAPrivateKey privateKey) {

    Objects.requireNonNull(privateKey, "privateKey");
    return privateKey.getModulus().bitLength();
  }

  @Override
  public int getKeyLength(RSAPublicKey publicKey) {

    Objects.requireNonNull(publicKey, "publicKey");
    return publicKey.getModulus().bitLength();
  }

}
