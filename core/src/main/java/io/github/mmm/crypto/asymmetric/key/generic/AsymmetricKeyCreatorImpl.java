package io.github.mmm.crypto.asymmetric.key.generic;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;

import io.github.mmm.crypto.asymmetric.key.AbstractAsymmetricKeyCreator;
import io.github.mmm.crypto.asymmetric.key.AbstractAsymmetricKeyPair;
import io.github.mmm.crypto.asymmetric.key.AsymmetricKeyCreator;
import io.github.mmm.crypto.asymmetric.key.AsymmetricKeyPair;
import io.github.mmm.crypto.asymmetric.key.AsymmetricKeyPairFactorySimple;
import io.github.mmm.crypto.key.KeyCreator;
import io.github.mmm.crypto.provider.SecurityProvider;
import io.github.mmm.crypto.random.RandomFactory;

/**
 * Generic implementation of {@link KeyCreator}. If available you should prefer implementations for specific
 * algorithms according {@code SecurityAccess*} classes (e.g.
 * {@link io.github.mmm.crypto.asymmetric.access.rsa.Rsa}).
 *
 * @param <PR> type of {@link PrivateKey}.
 * @param <PU> type of {@link PublicKey}.
 * @param <PAIR> type of {@link AsymmetricKeyPair}.
 * @since 1.0.0
 */
public class AsymmetricKeyCreatorImpl<PR extends PrivateKey, PU extends PublicKey, PAIR extends AbstractAsymmetricKeyPair<PR, PU>>
    extends AbstractAsymmetricKeyCreator<PR, PU, PAIR> {

  private final AsymmetricKeyPairFactorySimple<PR, PU, PAIR> keyPairFactory;

  /**
   * The constructor.
   *
   * @param keyFactory the {@link KeyFactory}.
   * @param keyLength the {@link #getKeyLength() key length}.
   * @param provider the security {@link SecurityProvider}.
   * @param keyPairFactory the {@link AsymmetricKeyPairFactorySimple}.
   * @param randomFactory the {@link RandomFactory}.
   */
  public AsymmetricKeyCreatorImpl(KeyFactory keyFactory, int keyLength, SecurityProvider provider,
      AsymmetricKeyPairFactorySimple<PR, PU, PAIR> keyPairFactory, RandomFactory randomFactory) {

    super(keyFactory, keyLength, provider, randomFactory);
    this.keyPairFactory = keyPairFactory;
  }

  @Override
  public PAIR createKeyPair(PR privateKey, PU publicKey) {

    return this.keyPairFactory.createKeyPair(privateKey, publicKey);
  }

  @Override
  public int getKeyLength(PR privateKey) {

    return getKeyLength();
  }

  @Override
  public int getKeyLength(PU publicKey) {

    return getKeyLength();
  }

  /**
   * @param algorithm the {@link #getAlgorithm() algorithm}.
   * @param keyLength the {@link #getKeyLength() key length}.
   * @return the {@link AsymmetricKeyCreator}.
   */
  public static AsymmetricKeyCreator<PrivateKey, PublicKey, AsymmetricKeyPairGeneric> of(String algorithm, int keyLength) {

    return of(algorithm, keyLength, null, null);
  }

  /**
   * @param algorithm the {@link #getAlgorithm() algorithm}.
   * @param keyLength the {@link #getKeyLength() key length}.
   * @param randomFactory the {@link RandomFactory}.
   * @return the {@link AsymmetricKeyCreator}.
   */
  public static AsymmetricKeyCreator<PrivateKey, PublicKey, AsymmetricKeyPairGeneric> of(String algorithm, int keyLength,
      RandomFactory randomFactory) {

    return of(algorithm, keyLength, null, randomFactory);
  }

  /**
   * @param algorithm the {@link #getAlgorithm() algorithm}.
   * @param keyLength the {@link #getKeyLength() key length}.
   * @param provider the {@link SecurityProvider}.
   * @param randomFactory the {@link RandomFactory}.
   * @return the {@link AsymmetricKeyCreator}.
   */
  public static AsymmetricKeyCreator<PrivateKey, PublicKey, AsymmetricKeyPairGeneric> of(String algorithm, int keyLength,
      SecurityProvider provider, RandomFactory randomFactory) {

    if (provider == null) {
      provider = SecurityProvider.DEFAULT;
    }
    KeyFactory keyFactory = provider.createKeyFactory(algorithm);
    return new AsymmetricKeyCreatorImpl<>(keyFactory, keyLength, provider, AsymmetricKeyPairFactoryGeneric.INSTANCE,
        randomFactory);
  }

}
