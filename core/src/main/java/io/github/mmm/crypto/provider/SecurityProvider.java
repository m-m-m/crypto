package io.github.mmm.crypto.provider;

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

/// Abstraction of [Provider].
///
/// @since 1.0.0
public final class SecurityProvider {

  /// The Java default [SecurityProvider] (JCE).
  public static final SecurityProvider DEFAULT = new SecurityProvider();

  /// The [SecurityProvider] for bouncy castle.
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

  /// @param algorithm the [key-pair generator algorithm][KeyPairGenerator#getAlgorithm()]. See <a href=
        "https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#keypairgenerator-algorithms">KeyPairGenerator
  ///        Algorithms</a>.
  /// @return the (uninitialized) [KeyPairGenerator] instance.
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

  /// @param algorithm the [secret key factory algorithm][SecretKeyFactory#getAlgorithm()]. See <a href=
        "https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#secretkeyfactory-algorithms">SecretKeyFactory
  ///        Algorithms</a>.
  /// @return the (uninitialized) [SecretKeyFactory] instance.
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

  /// @param algorithm the [signature algorithm][Signature#getAlgorithm()]. See <a href=
        "https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#signature-algorithms">Signature
  ///        Algorithms</a>.
  /// @return the (uninitialized) [Signature] instance.
  /// @see io.github.mmm.crypto.asymmetric.sign.SignatureAlgorithm
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

  /// @param transformation the [encryption algorithm][Cipher#getAlgorithm()] or
  ///        [transformation][io.github.mmm.crypto.crypt.CipherTransformation#getTransformation()].
  /// @return the (uninitialized) [Cipher] instance.
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

  /// @param algorithm the [hash algorithm][MessageDigest#getAlgorithm()] (see <a href=
        "https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#messagedigest-algorithms">MessageDigest
  ///        Algorithms</a>).
  /// @return the (uninitialized) [MessageDigest] instance.
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

  /// @param algorithm the [secure random algorithm][SecureRandom#getAlgorithm()] (see <a href=
        "https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#securerandom-number-generation-algorithms">SecureRandom
  ///        Number Generation Algorithms</a>).
  /// @return the [SecureRandom] instance.
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

  /// @param type the [type][CertificateFactory#getType()] of the [CertificateFactory] (see <a href=
        "https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#certificatefactory-types">CertificateFactory
  ///        Types</a>).
  /// @return the [CertificateFactory] instance.
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

  /// @param algorithm the [algorithm][KeyFactory#getAlgorithm()] of the [KeyFactory] (see <a href=
        "https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#keyfactory-algorithms">KeyFactory
  ///        Algorithms</a>).
  /// @return the [KeyFactory] instance.
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

  /// @param type the [type][KeyStore#getType()] of the [KeyStore] (see <a href=
        "https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#keystore-types">KeyStore
  ///        Types</a>).
  /// @return the [KeyStore] instance.
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

  /// @param name the [provider name][Provider#getName()].
  /// @return the [SecurityProvider].
  public static SecurityProvider of(String name) {

    if (BC.providerName.equals(name)) {
      return BC;
    } else {
      return new SecurityProvider(name);
    }
  }

  /// @param provider the [Provider] to wrap.
  /// @return the [SecurityProvider].
  public static SecurityProvider of(Provider provider) {

    Objects.requireNonNull(provider, "provider");
    return new SecurityProvider(provider);
  }

}
