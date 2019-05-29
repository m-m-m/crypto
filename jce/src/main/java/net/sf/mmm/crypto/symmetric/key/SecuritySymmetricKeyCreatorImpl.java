package net.sf.mmm.crypto.symmetric.key;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;

import net.sf.mmm.crypto.algorithm.AbstractCryptoAlgorithmWithProvider;

/**
 * Implementation of {@link SecuritySymmetricKeyCreator}.
 *
 * @param <K> type of {@link SecretKey}.
 * @since 1.0.0
 */
public class SecuritySymmetricKeyCreatorImpl<K extends SecretKey> extends AbstractCryptoAlgorithmWithProvider
    implements SecuritySymmetricKeyCreator<K> {

  private final SecuritySymmetricKeyConfig config;

  private SecretKeyFactory keyFactory;

  /**
   * The constructor.
   *
   * @param config the {@link SecuritySymmetricKeyConfig}.
   */
  public SecuritySymmetricKeyCreatorImpl(SecuritySymmetricKeyConfig config) {

    super(config.getProvider());
    this.config = config;
  }

  @Override
  public String getAlgorithm() {

    return this.config.getAlgorithm();
  }

  @Override
  public int getKeyLength() {

    return this.config.getKeyLength();
  }

  @Override
  public int getKeyLength(K key) {

    return this.config.getKeyLength(key, getKeyFactory());
  }

  @SuppressWarnings("unchecked")
  @Override
  public K createKey(String password) {

    try {
      KeySpec keySpec = this.config.getKeySpecFactory().createKeySpec(password);
      SecretKey secretKey = getKeyFactory().generateSecret(keySpec);
      return (K) secretKey;
    } catch (Exception e) {
      throw new IllegalStateException("Failed to create key pair for algorithm '" + getAlgorithm() + "'.", e);
    }
  }

  @SuppressWarnings("unchecked")
  @Override
  public K createKey(byte[] key) {

    try {
      SecretKey secretKey = getKeyFactory().generateSecret(new SecretKeySpec(key, getAlgorithm()));
      return (K) secretKey;
    } catch (InvalidKeySpecException e) {
      throw new IllegalStateException(e);
    }
  }

  @Override
  public byte[] asData(K key) {

    return key.getEncoded();
  }

  private SecretKeyFactory getKeyFactory() {

    if (this.keyFactory == null) {
      this.keyFactory = this.provider.createSecretKeyFactory(getAlgorithm());
    }
    return this.keyFactory;
  }

}
