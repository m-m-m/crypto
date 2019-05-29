package net.sf.mmm.security.api.asymmetric.key.generic;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;

import net.sf.mmm.security.api.asymmetric.key.AbstractSecurityAsymmetricKeyCreator;
import net.sf.mmm.security.api.asymmetric.key.AbstractSecurityAsymmetricKeyPair;
import net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyCreator;
import net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyPair;
import net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyPairFactorySimple;
import net.sf.mmm.security.api.key.SecurityKeyCreator;
import net.sf.mmm.security.api.provider.SecurityProvider;
import net.sf.mmm.security.api.random.SecurityRandomFactory;

/**
 * Generic implementation of {@link SecurityKeyCreator}. If available you should prefer implementations for specific
 * algorithms according {@code SecurityAccess*} classes (e.g.
 * {@link net.sf.mmm.security.api.asymmetric.access.rsa.Rsa}).
 *
 * @param <PR> type of {@link PrivateKey}.
 * @param <PU> type of {@link PublicKey}.
 * @param <PAIR> type of {@link SecurityAsymmetricKeyPair}.
 * @since 1.0.0
 */
public class SecurityAsymmetricKeyCreatorImpl<PR extends PrivateKey, PU extends PublicKey, PAIR extends AbstractSecurityAsymmetricKeyPair<PR, PU>>
    extends AbstractSecurityAsymmetricKeyCreator<PR, PU, PAIR> {

  private final SecurityAsymmetricKeyPairFactorySimple<PR, PU, PAIR> keyPairFactory;

  /**
   * The constructor.
   *
   * @param keyFactory the {@link KeyFactory}.
   * @param keyLength the {@link #getKeyLength() key length}.
   * @param provider the security {@link SecurityProvider}.
   * @param keyPairFactory the {@link SecurityAsymmetricKeyPairFactorySimple}.
   * @param randomFactory the {@link SecurityRandomFactory}.
   */
  public SecurityAsymmetricKeyCreatorImpl(KeyFactory keyFactory, int keyLength, SecurityProvider provider,
      SecurityAsymmetricKeyPairFactorySimple<PR, PU, PAIR> keyPairFactory, SecurityRandomFactory randomFactory) {

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
   * @return the {@link SecurityAsymmetricKeyCreator}.
   */
  public static SecurityAsymmetricKeyCreator<PrivateKey, PublicKey, SecurityAsymmetricKeyPairGeneric> of(String algorithm, int keyLength) {

    return of(algorithm, keyLength, null, null);
  }

  /**
   * @param algorithm the {@link #getAlgorithm() algorithm}.
   * @param keyLength the {@link #getKeyLength() key length}.
   * @param randomFactory the {@link SecurityRandomFactory}.
   * @return the {@link SecurityAsymmetricKeyCreator}.
   */
  public static SecurityAsymmetricKeyCreator<PrivateKey, PublicKey, SecurityAsymmetricKeyPairGeneric> of(String algorithm, int keyLength,
      SecurityRandomFactory randomFactory) {

    return of(algorithm, keyLength, null, randomFactory);
  }

  /**
   * @param algorithm the {@link #getAlgorithm() algorithm}.
   * @param keyLength the {@link #getKeyLength() key length}.
   * @param provider the {@link SecurityProvider}.
   * @param randomFactory the {@link SecurityRandomFactory}.
   * @return the {@link SecurityAsymmetricKeyCreator}.
   */
  public static SecurityAsymmetricKeyCreator<PrivateKey, PublicKey, SecurityAsymmetricKeyPairGeneric> of(String algorithm, int keyLength,
      SecurityProvider provider, SecurityRandomFactory randomFactory) {

    if (provider == null) {
      provider = SecurityProvider.DEFAULT;
    }
    KeyFactory keyFactory = provider.createKeyFactory(algorithm);
    return new SecurityAsymmetricKeyCreatorImpl<>(keyFactory, keyLength, provider, SecurityAsymmetricKeyPairFactoryGeneric.INSTANCE,
        randomFactory);
  }

}
