package net.sf.mmm.security.api.asymmetric.key;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import net.sf.mmm.security.api.SecurityBinaryFormat;
import net.sf.mmm.security.api.algorithm.SecurityAlgorithmImplWithRandom;
import net.sf.mmm.security.api.asymmetric.key.generic.SecurityAsymmetricKeyPairFactoryEncoded;
import net.sf.mmm.security.api.key.SecurityKeyCreator;
import net.sf.mmm.security.api.provider.SecurityProvider;
import net.sf.mmm.security.api.random.SecurityRandomFactory;

/**
 * Abstract base implementation of {@link SecurityKeyCreator}.
 *
 * @param <PR> type of wrapped {@link PrivateKey}.
 * @param <PU> type of wrapped {@link PublicKey}.
 * @param <PAIR> type of {@link SecurityAsymmetricKeyPair}.
 * @since 1.0.0
 */
public abstract class AbstractSecurityAsymmetricKeyCreator<PR extends PrivateKey, PU extends PublicKey, PAIR extends AbstractSecurityAsymmetricKeyPair<PR, PU>>
    extends SecurityAlgorithmImplWithRandom implements SecurityAsymmetricKeyCreator<PR, PU, PAIR> {

  private final Map<String, SecurityAsymmetricKeyPairFactory<PR, PU, PAIR>> format2factoryMap;

  private final List<String> formatOrderList;

  private final int keyLength;

  /**
   * The constructor.
   *
   * @param keyFactory the {@link KeyFactory}.
   * @param keyLength the {@link #getKeyLength() key length}.
   * @param provider the security {@link Provider}.
   * @param randomFactory the {@link SecurityRandomFactory}.
   */
  public AbstractSecurityAsymmetricKeyCreator(KeyFactory keyFactory, int keyLength, SecurityProvider provider,
      SecurityRandomFactory randomFactory) {

    super(keyFactory.getAlgorithm(), provider, randomFactory);
    this.keyLength = keyLength;
    this.format2factoryMap = new HashMap<>();
    this.formatOrderList = new ArrayList<>();
    this.format2factoryMap.put(SecurityBinaryFormat.FORMAT_ENCODED, new SecurityAsymmetricKeyPairFactoryEncoded<>(keyFactory, this));
  }

  @Override
  public int getKeyLength() {

    return this.keyLength;
  }

  /**
   * Please register in proper order of trials for auto-detection.
   *
   * @param factory the {@link SecurityAsymmetricKeyPairFactory} to register.
   */
  protected void register(SecurityAsymmetricKeyPairFactory<PR, PU, PAIR> factory) {

    register(factory, SecurityBinaryFormat.FORMAT_COMPACT);
  }

  /**
   * Please register in proper order of trials for auto-detection.
   *
   * @param factory the {@link SecurityAsymmetricKeyPairFactory} to register.
   * @param format the format to register as.
   */
  protected void register(SecurityAsymmetricKeyPairFactory<PR, PU, PAIR> factory, String format) {

    SecurityAsymmetricKeyPairFactory<PR, PU, PAIR> old = this.format2factoryMap.put(format, factory);
    if (old != null) {
      throw new IllegalStateException("Duplicate format " + format + " registered!");
    }
    this.formatOrderList.add(format);
  }

  private List<String> getFormatOrderList() {

    if (this.formatOrderList.size() < this.format2factoryMap.size()) {
      this.formatOrderList.add(SecurityBinaryFormat.FORMAT_ENCODED);
    }
    return this.formatOrderList;
  }

  private SecurityAsymmetricKeyPairFactory<PR, PU, PAIR> getKeyPairFactory(String format) {

    SecurityAsymmetricKeyPairFactory<PR, PU, PAIR> factory = this.format2factoryMap.get(format);
    if (factory == null) {
      if (SecurityBinaryFormat.FORMAT_COMPACT.equals(format)) {
        factory = this.format2factoryMap.get(SecurityBinaryFormat.FORMAT_ENCODED);
      }
      if (factory == null) {
        throw new IllegalArgumentException(format);
      }
    }
    return factory;
  }

  @Override
  public PR createPrivateKey(byte[] data, String format) {

    if (format == null) {
      for (String format2detect : getFormatOrderList()) {
        PR privateKey = createPrivateKey(data, format2detect);
        if (privateKey != null) {
          return privateKey;
        }
      }
      throw new IllegalStateException();
    }
    return getKeyPairFactory(format).createPrivateKey(data);
  }

  @Override
  public byte[] asData(PR privateKey, String format) {

    return getKeyPairFactory(format).asData(privateKey);
  }

  @Override
  public PU createPublicKey(byte[] data, String format) {

    if (format == null) {
      for (String format2detect : getFormatOrderList()) {
        PU publicKey = createPublicKey(data, format2detect);
        if (publicKey != null) {
          return publicKey;
        }
      }
      throw new IllegalStateException();
    }
    return getKeyPairFactory(format).createPublicKey(data);
  }

  @Override
  public byte[] asData(PU publicKey, String format) {

    return getKeyPairFactory(format).asData(publicKey);
  }

  @Override
  public PAIR createKeyPair(byte[] data, String format) {

    if (format == null) {
      for (String format2detect : getFormatOrderList()) {
        PAIR keyPair = createKeyPair(data, format2detect);
        if (keyPair != null) {
          return keyPair;
        }
      }
      throw new IllegalStateException();
    }
    return getKeyPairFactory(format).createKeyPair(data);
  }

  @Override
  public byte[] asData(PAIR keyPair, String format) {

    return getKeyPairFactory(format).asData(keyPair);
  }

  @SuppressWarnings("unchecked")
  @Override
  public PAIR generateKeyPair() {

    try {
      KeyPairGenerator keyPairGenerator = getProvider().createKeyPairGenerator(getAlgorithm());
      init(keyPairGenerator);
      KeyPair key = keyPairGenerator.generateKeyPair();
      PR privateKey = (PR) key.getPrivate();
      PU publicKey = (PU) key.getPublic();
      return createKeyPair(privateKey, publicKey);
    } catch (Exception e) {
      throw creationFailedException(e, KeyPair.class);
    }
  }

  /**
   * @param keyPairGenerator the {@link KeyPairGenerator} to {@link KeyPairGenerator#initialize(int) initialize}.
   * @throws Exception on error.
   */
  protected void init(KeyPairGenerator keyPairGenerator) throws Exception {

    keyPairGenerator.initialize(this.keyLength, createSecureRandom());
  }

}
