package net.sf.mmm.crypto.provider;

import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;

/**
 * Abstraction of {@link Provider}.
 *
 * @since 1.0.0
 */
public final class SecurityProvider {

  /** The Java default {@link SecurityProvider} (JCE). */
  public static final SecurityProvider DEFAULT = new SecurityProvider();

  /** The {@link SecurityProvider} for bouncy castle. */
  public static final SecurityProvider BC = new SecurityProvider("BC");

  private final Provider provider;

  private final String providerName;

  private SecurityProvider() {

    super();
    this.provider = null;
    this.providerName = null;
  }

  private SecurityProvider(String providerName) {

    this(null, providerName);
  }

  private SecurityProvider(Provider provider) {

    this(provider, provider.getName());
  }

  private SecurityProvider(Provider provider, String providerName) {

    super();
    Objects.requireNonNull(providerName, "providerName");
    this.provider = provider;
    this.providerName = providerName;
  }

  /**
   * @param algorithm the {@link KeyPairGenerator#getAlgorithm() key-pair generator algorithm}. See <a href=
   *        "https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#keypairgenerator-algorithms">KeyPairGenerator
   *        Algorithms</a>.
   * @return the (uninitialized) {@link KeyPairGenerator} instance.
   *
   */
  public KeyPairGenerator createKeyPairGenerator(String algorithm) {

    try {
      Objects.requireNonNull(algorithm, "algorithm");
      if (this.provider != null) {
        return KeyPairGenerator.getInstance(algorithm, this.provider);
      } else if (this.providerName != null) {
        return KeyPairGenerator.getInstance(algorithm, this.providerName);
      } else {
        return KeyPairGenerator.getInstance(algorithm);
      }
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("Unsupported key-pair-generator algorithm '" + algorithm + "' for " + toString(), e);
    } catch (NoSuchProviderException e) {
      throw new IllegalStateException("Unsupported security provider '" + this.providerName + "'.", e);
    }
  }

  /**
   * @param algorithm the {@link SecretKeyFactory#getAlgorithm() secret key factory algorithm}. See <a href=
   *        "https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#secretkeyfactory-algorithms">SecretKeyFactory
   *        Algorithms</a>.
   * @return the (uninitialized) {@link SecretKeyFactory} instance.
   */
  public SecretKeyFactory createSecretKeyFactory(String algorithm) {

    try {
      Objects.requireNonNull(algorithm, "algorithm");
      if (this.provider != null) {
        return SecretKeyFactory.getInstance(algorithm, this.provider);
      } else if (this.providerName != null) {
        return SecretKeyFactory.getInstance(algorithm, this.providerName);
      } else {
        return SecretKeyFactory.getInstance(algorithm);
      }
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("Unsupported secret-key-factory algorithm '" + algorithm + "' for " + toString(), e);
    } catch (NoSuchProviderException e) {
      throw new IllegalStateException("Unsupported security provider '" + this.providerName + "'.", e);
    }
  }

  /**
   * @param algorithm the {@link Signature#getAlgorithm() signature algorithm}. See <a href=
   *        "https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#signature-algorithms">Signature
   *        Algorithms</a>.
   * @return the (uninitialized) {@link Signature} instance.
   * @see net.sf.mmm.crypto.asymmetric.sign.SignatureAlgorithm
   */
  public Signature createSignature(String algorithm) {

    Objects.requireNonNull(algorithm, "algorithm");
    try {
      if (this.provider != null) {
        return Signature.getInstance(algorithm, this.provider);
      } else if (this.providerName != null) {
        return Signature.getInstance(algorithm, this.providerName);
      } else {
        return Signature.getInstance(algorithm);
      }
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("Unsupported signature algorithm '" + algorithm + "' for " + toString(), e);
    } catch (NoSuchProviderException e) {
      throw new IllegalStateException("Unsupported security provider '" + this.providerName + "'.", e);
    }
  }

  /**
   * @param transformation the {@link Cipher#getAlgorithm() encryption algorithm} or
   *        {@link net.sf.mmm.crypto.crypt.CipherTransformation#getTransformation() transformation}.
   * @return the (uninitialized) {@link Cipher} instance.
   *
   */
  public Cipher createCipher(String transformation) {

    Objects.requireNonNull(transformation, "transformation");
    try {
      if (this.provider != null) {
        return Cipher.getInstance(transformation, this.provider);
      } else if (this.providerName != null) {
        return Cipher.getInstance(transformation, this.providerName);
      } else {
        return Cipher.getInstance(transformation);
      }
    } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
      throw new IllegalStateException("Unsupported encryption algorithm (cipher transformation) '" + transformation + "' for " + toString(),
          e);
    } catch (NoSuchProviderException e) {
      throw new IllegalStateException("Unsupported security provider '" + this.providerName + "'.", e);
    }
  }

  /**
   * @param algorithm the {@link MessageDigest#getAlgorithm() hash algorithm} (see <a href=
   *        "https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#messagedigest-algorithms">MessageDigest
   *        Algorithms</a>).
   * @return the (uninitialized) {@link MessageDigest} instance.
   *
   */
  public MessageDigest createDigest(String algorithm) {

    Objects.requireNonNull(algorithm, "algorithm");
    try {
      if (this.provider != null) {
        return MessageDigest.getInstance(algorithm, this.provider);
      } else if (this.providerName != null) {
        return MessageDigest.getInstance(algorithm, this.providerName);
      } else {
        return MessageDigest.getInstance(algorithm);
      }
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("Unsupported hash algorithm '" + algorithm + "' for " + toString(), e);
    } catch (NoSuchProviderException e) {
      throw new IllegalStateException("Unsupported security provider '" + this.providerName + "'.", e);
    }
  }

  /**
   * @param algorithm the {@link SecureRandom#getAlgorithm() secure random algorithm} (see <a href=
   *        "https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#securerandom-number-generation-algorithms">SecureRandom
   *        Number Generation Algorithms</a>).
   * @return the {@link SecureRandom} instance.
   */
  public SecureRandom createSecureRandom(String algorithm) {

    try {
      Objects.requireNonNull(algorithm, "algorithm");
      if (this.provider != null) {
        return SecureRandom.getInstance(algorithm, this.provider);
      } else if (this.providerName != null) {
        return SecureRandom.getInstance(algorithm, this.providerName);
      } else {
        return SecureRandom.getInstance(algorithm);
      }
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("Unsupported secure-random-factory algorithm '" + algorithm + "' for " + toString(), e);
    } catch (NoSuchProviderException e) {
      throw new IllegalStateException("Unsupported security provider '" + this.providerName + "'.", e);
    }
  }

  /**
   * @param type the {@link CertificateFactory#getType() type} of the {@link CertificateFactory} (see <a href=
   *        "https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#certificatefactory-types">CertificateFactory
   *        Types</a>).
   * @return the {@link CertificateFactory} instance.
   */
  public CertificateFactory createCertificateFactory(String type) {

    try {
      Objects.requireNonNull(type, "type");
      if (this.provider != null) {
        return CertificateFactory.getInstance(type, this.provider);
      } else if (this.providerName != null) {
        return CertificateFactory.getInstance(type, this.providerName);
      } else {
        return CertificateFactory.getInstance(type);
      }
    } catch (CertificateException e) {
      throw new IllegalStateException("Unsupported certificate-factory type '" + type + "' for " + toString(), e);
    } catch (NoSuchProviderException e) {
      throw new IllegalStateException("Unsupported security provider '" + this.providerName + "'.", e);
    }
  }

  /**
   * @param algorithm the {@link KeyFactory#getAlgorithm() algorithm} of the {@link KeyFactory} (see <a href=
   *        "https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#keyfactory-algorithms">KeyFactory
   *        Algorithms</a>).
   * @return the {@link KeyFactory} instance.
   */
  public KeyFactory createKeyFactory(String algorithm) {

    try {
      Objects.requireNonNull(algorithm, "algorithm");
      if (this.provider != null) {
        return KeyFactory.getInstance(algorithm, this.provider);
      } else if (this.providerName != null) {
        return KeyFactory.getInstance(algorithm, this.providerName);
      } else {
        return KeyFactory.getInstance(algorithm);
      }
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("Unsupported key-factory algorithm '" + algorithm + "' for " + toString(), e);
    } catch (NoSuchProviderException e) {
      throw new IllegalStateException("Unsupported security provider '" + this.providerName + "'.", e);
    }
  }

  /**
   * @param type the {@link KeyStore#getType() type} of the {@link KeyStore} (see <a href=
   *        "https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#keystore-types">KeyStore
   *        Types</a>).
   * @return the {@link KeyStore} instance.
   */
  public KeyStore createKeyStore(String type) {

    try {
      Objects.requireNonNull(type, "type");
      if (this.provider != null) {
        return KeyStore.getInstance(type, this.provider);
      } else if (this.providerName != null) {
        return KeyStore.getInstance(type, this.providerName);
      } else {
        return KeyStore.getInstance(type);
      }
    } catch (KeyStoreException e) {
      throw new IllegalStateException("Unsupported key-store type '" + type + "' for " + toString(), e);
    } catch (NoSuchProviderException e) {
      throw new IllegalStateException("Unsupported security provider '" + this.providerName + "'.", e);
    }
  }

  @Override
  public String toString() {

    if (this.providerName == null) {
      return "SecurityProvider: default";
    } else {
      return "SecurityProdivder: " + this.providerName;
    }
  }

  /**
   * @param name the {@link Provider#getName() provider name}.
   * @return the {@link SecurityProvider}.
   */
  public static SecurityProvider of(String name) {

    if (BC.providerName.equals(name)) {
      return BC;
    } else {
      return new SecurityProvider(name);
    }
  }

  /**
   * @param provider the {@link Provider} to wrap.
   * @return the {@link SecurityProvider}.
   */
  public static SecurityProvider of(Provider provider) {

    Objects.requireNonNull(provider, "provider");
    return new SecurityProvider(provider);
  }

}
