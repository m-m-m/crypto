package io.github.mmm.crypto.asymmetric.key;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * Abstract base implementation of {@link AsymmetricKeyPairFactory} using {@link KeyFactory}.
 *
 * @param <PR> type of {@link PrivateKey}.
 * @param <PU> type of {@link PublicKey}.
 * @param <PAIR> type of {@link AsymmetricKeyPair}.
 * @since 1.0.0
 */
public abstract class AbstractAsymmetricKeyPairFactory<PR extends PrivateKey, PU extends PublicKey, PAIR extends AbstractAsymmetricKeyPair<PR, PU>>
    implements AsymmetricKeyPairFactory<PR, PU, PAIR> {

  private final KeyFactory keyFactory;

  /**
   * The constructor.
   *
   * @param keyFactory the {@link KeyFactory}.
   */
  public AbstractAsymmetricKeyPairFactory(KeyFactory keyFactory) {

    super();
    this.keyFactory = keyFactory;
  }

  /**
   * @return the underlying {@link KeyFactory}.
   */
  public KeyFactory getKeyFactory() {

    return this.keyFactory;
  }

  /**
   * @param keySpec the {@link KeySpec}.
   * @return the {@link PrivateKey}.
   */
  @SuppressWarnings("unchecked")
  protected PR createPrivateKey(KeySpec keySpec) {

    try {
      return (PR) this.keyFactory.generatePrivate(keySpec);
    } catch (InvalidKeySpecException e) {
      throw new IllegalArgumentException("Failed to create private key from spec using algorithm " + this.keyFactory.getAlgorithm() + ".",
          e);
    }
  }

  /**
   * @param keySpec the {@link KeySpec}.
   * @return the {@link PublicKey}.
   */
  @SuppressWarnings("unchecked")
  protected PU createPublicKey(KeySpec keySpec) {

    try {
      return (PU) this.keyFactory.generatePublic(keySpec);
    } catch (InvalidKeySpecException e) {
      throw new IllegalArgumentException("Failed to create public key from spec using algorithm " + this.keyFactory.getAlgorithm() + ".",
          e);
    }
  }

  @Override
  public String toString() {

    return getClass().getSimpleName() + " for " + this.keyFactory.getAlgorithm();
  }

}
