package io.github.mmm.crypto.asymmetric.key.rsa;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;

import io.github.mmm.crypto.asymmetric.key.AbstractAsymmetricKeyCreator;
import io.github.mmm.crypto.asymmetric.key.AsymmetricKeyCreator;
import io.github.mmm.crypto.provider.SecurityProvider;
import io.github.mmm.crypto.random.RandomFactory;

/**
 * Implementation of {@link AsymmetricKeyCreator} for {@link AsymmetricKeyPairRsa RSA}.
 *
 * @since 1.0.0
 */
public class AsymmetricKeyCreatorRsa
    extends AbstractAsymmetricKeyCreator<RSAPrivateKey, RSAPublicKey, AsymmetricKeyPairRsa> {

  /**
   * The constructor.
   *
   * @param keyLength the {@link #getKeyLength() key length}.
   */
  public AsymmetricKeyCreatorRsa(int keyLength) {

    this(keyLength, null, null);
  }

  /**
   * The constructor.
   *
   * @param keyLength the {@link #getKeyLength() key length}.
   * @param provider the {@link #getProvider() provider}.
   * @param randomFactory the {@link #getRandomFactory() random factory}.
   */
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
