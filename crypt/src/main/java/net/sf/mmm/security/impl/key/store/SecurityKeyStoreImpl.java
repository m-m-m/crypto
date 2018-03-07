package net.sf.mmm.security.impl.key.store;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.util.List;
import java.util.Objects;

import javax.crypto.SecretKey;

import net.sf.mmm.security.api.cert.SecurityCertificate;
import net.sf.mmm.security.api.cert.SecurityCertificatePath;
import net.sf.mmm.security.api.io.SecurityDataResource;
import net.sf.mmm.security.api.key.SecurityKey;
import net.sf.mmm.security.api.key.SecurityKeySet;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyPair;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyPairGeneric;
import net.sf.mmm.security.api.key.asymmetric.SecurityPrivateKey;
import net.sf.mmm.security.api.key.asymmetric.SecurityPrivateKeyGeneric;
import net.sf.mmm.security.api.key.asymmetric.SecurityPublicKey;
import net.sf.mmm.security.api.key.asymmetric.SecurityPublicKeyGeneric;
import net.sf.mmm.security.api.key.store.SecurityKeyStore;
import net.sf.mmm.security.api.key.store.SecurityKeyStoreConfig;
import net.sf.mmm.security.api.key.symmetric.SecuritySymmetricKey;
import net.sf.mmm.security.api.key.symmetric.SecuritySymmetricKeyGeneric;

/**
 * Implementation of {@link SecurityKeyStore}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityKeyStoreImpl implements SecurityKeyStore {

  private static final Certificate[] NO_CHAIN = null;

  private final SecurityKeyStoreConfig config;

  private final Provider provider;

  private final char[] password;

  private KeyStore keyStore;

  /**
   * The constructor.
   *
   * @param config the {@link SecurityKeyStoreConfig}.
   * @param provider the {@link Provider}.
   */
  public SecurityKeyStoreImpl(SecurityKeyStoreConfig config, Provider provider) {

    super();
    this.config = config;
    this.provider = provider;
    this.password = getChars(config.getPassword());
  }

  private static char[] getChars(String password) {

    if (password == null) {
      return null;
    } else {
      return password.toCharArray();
    }
  }

  @Override
  public KeyStore getKeyStore() {

    if (this.keyStore == null) {
      String type = this.config.getType();
      KeyStore ks;
      try {
        if (this.provider == null) {
          ks = KeyStore.getInstance(type);
        } else {
          ks = KeyStore.getInstance(type, this.provider);
        }
      } catch (Exception e) {
        throw new IllegalStateException("Failed to create KeyStore of type " + type + "!", e);
      }
      SecurityDataResource resource = this.config.getResource();
      if (resource.exists()) {
        try (InputStream in = resource.openInputStream()) {
          ks.load(in, this.password);
        } catch (Exception e) {
          throw new IllegalStateException(
              "Failed to load KeyStore of type " + type + " from " + resource.getUri() + "!", e);
        }
      } else {
        try {
          ks.load(null, null);
        } catch (Exception e) {
          throw new IllegalStateException("Failed to initialize KeyStore of type " + type + "!", e);
        }
      }
      this.keyStore = ks;
    }
    return this.keyStore;
  }

  @Override
  public SecurityKeySet getKeyPair(String alias, String keyPassword) {

    try {
      char[] pwd = keyPassword.toCharArray();
      KeyStore ks = getKeyStore();
      Key key = ks.getKey(alias, pwd);
      if (key instanceof PrivateKey) {
        SecurityPrivateKey privateKey = new SecurityPrivateKeyGeneric((PrivateKey) key);
        Certificate certificate = ks.getCertificate(alias);
        SecurityPublicKey publicKey = new SecurityPublicKeyGeneric(certificate.getPublicKey());
        return new SecurityAsymmetricKeyPairGeneric(privateKey, publicKey);
      } else if (key instanceof SecretKey) {
        return new SecuritySymmetricKeyGeneric((SecretKey) key);
      } else {
        throw new IllegalStateException("Unsupported key (class: " + key.getClass().getSimpleName() + ", format: "
            + key.getFormat() + "algorithm: " + key.getAlgorithm() + ")");
      }
    } catch (Exception e) {
      throw new IllegalStateException("Failed to get Key with alias " + alias + " from KeyStore of type "
          + this.config.getType() + " at " + this.config.getResource().getUri() + "!", e);
    }
  }

  @Override
  public void setKeyPair(String alias, SecurityAsymmetricKeyPair keyPair, String password,
      SecurityCertificatePath certificatePath) {

    setKeyPairInternal(alias, keyPair.getPrivateKey(), password, certificatePath);
  }

  @Override
  public void setKeyPair(String alias, SecuritySymmetricKey key, String password) {

    setKeyPairInternal(alias, key, password, null);
  }

  private void setKeyPairInternal(String alias, SecurityKey<?> secureKey, String password,
      SecurityCertificatePath certificatePath) {

    Objects.requireNonNull(secureKey, "secureKey");
    Certificate[] chain;
    if (certificatePath == null) {
      chain = NO_CHAIN;
    } else {
      List<SecurityCertificate> certificates = certificatePath.getCertificates();
      chain = new Certificate[certificates.size()];
      for (int i = 0; i < chain.length; i++) {
        chain[i] = certificates.get(i).getCertificate();
      }
    }
    try {
      getKeyStore().setKeyEntry(alias, secureKey.getKey(), getChars(password), chain);
    } catch (Exception e) {
      throw new IllegalStateException("Failed to set Key with alias " + alias + " to KeyStore of type "
          + this.config.getType() + " at " + this.config.getResource().getUri() + "!", e);
    }
  }

  @Override
  public void save() {

    if (this.keyStore == null) {
      return;
    }
    SecurityDataResource resource = this.config.getResource();
    String type = this.config.getType();
    OutputStream outputStream = resource.openOutputStream();
    if (outputStream == null) { // for KeyStores of OS or specific hardware (PKCS11)
      try {
        this.keyStore.store(null, this.password);
      } catch (Exception e) {
        throw new IllegalStateException("Failed to save KeyStore of type " + type + " to " + resource.getUri() + "!",
            e);
      }
    } else {
      try (OutputStream out = outputStream) {
        this.keyStore.store(out, this.password);
      } catch (Exception e) {
        throw new IllegalStateException("Failed to save KeyStore of type " + type + " to " + resource.getUri() + "!",
            e);
      }
    }
  }

  @Override
  public String toString() {

    return this.config.getType() + "-KeyStore@" + this.config.getResource().getUri();
  }

}
