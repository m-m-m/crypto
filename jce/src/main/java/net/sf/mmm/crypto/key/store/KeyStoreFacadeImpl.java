package net.sf.mmm.crypto.key.store;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Objects;

import javax.crypto.SecretKey;

import net.sf.mmm.crypto.asymmetric.cert.CertificatePath;
import net.sf.mmm.crypto.asymmetric.key.AsymmetricKeyPair;
import net.sf.mmm.crypto.asymmetric.key.generic.AsymmetricKeyPairGeneric;
import net.sf.mmm.crypto.asymmetric.key.rsa.AsymmetricKeyPairRsa;
import net.sf.mmm.crypto.io.CryptoResource;
import net.sf.mmm.crypto.key.KeySet;
import net.sf.mmm.crypto.symmetric.key.SymmetricKeyGeneric;

/**
 * Implementation of {@link KeyStoreFacade}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class KeyStoreFacadeImpl implements KeyStoreFacade {

  private static final Certificate[] NO_CHAIN = null;

  private final KeyStoreConfig config;

  private final char[] password;

  private KeyStore keyStore;

  /**
   * The constructor.
   *
   * @param config the {@link KeyStoreConfig}.
   */
  public KeyStoreFacadeImpl(KeyStoreConfig config) {

    super();
    this.config = config;
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
      KeyStore ks = this.config.getProvider().createKeyStore(this.config.getType());
      CryptoResource resource = this.config.getResource();
      if (resource.exists()) {
        try (InputStream in = resource.openInputStream()) {
          ks.load(in, this.password);
        } catch (Exception e) {
          throw new IllegalStateException("Failed to load KeyStore of type " + type + " from " + resource.getUri() + "!", e);
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
  public KeySet getKey(String alias, String keyPassword) {

    try {
      char[] pwd = keyPassword.toCharArray();
      KeyStore ks = getKeyStore();
      Key key = ks.getKey(alias, pwd);
      if (key instanceof PrivateKey) {
        PrivateKey privateKey = (PrivateKey) key;
        Certificate certificate = ks.getCertificate(alias);
        PublicKey publicKey = certificate.getPublicKey();
        // TODO
        if (privateKey instanceof RSAPrivateKey) {
          return new AsymmetricKeyPairRsa((RSAPrivateKey) privateKey, (RSAPublicKey) publicKey);
        }
        return new AsymmetricKeyPairGeneric(privateKey, publicKey);
      } else if (key instanceof SecretKey) {
        return new SymmetricKeyGeneric<>((SecretKey) key);
      } else {
        throw new IllegalStateException("Unsupported key (class: " + key.getClass().getSimpleName() + ", format: " + key.getFormat()
            + "algorithm: " + key.getAlgorithm() + ")");
      }
    } catch (Exception e) {
      throw new IllegalStateException("Failed to get Key with alias " + alias + " from KeyStore of type " + this.config.getType() + " at "
          + this.config.getResource().getUri() + "!", e);
    }
  }

  @Override
  public void setKey(String alias, AsymmetricKeyPair<?, ?> keyPair, String password, CertificatePath certificatePath) {

    setKeyPairInternal(alias, keyPair.getPrivateKey(), password, certificatePath);
  }

  @Override
  public void setKey(String alias, SecretKey key, String password) {

    setKeyPairInternal(alias, key, password, null);
  }

  private void setKeyPairInternal(String alias, Key secureKey, String password, CertificatePath certificatePath) {

    Objects.requireNonNull(secureKey, "secureKey");
    Certificate[] chain;
    if (certificatePath == null) {
      chain = NO_CHAIN;
    } else {
      List<Certificate> certificates = certificatePath.getCertificates();
      chain = new Certificate[certificates.size()];
      for (int i = 0; i < chain.length; i++) {
        chain[i] = certificates.get(i);
      }
    }
    try {
      getKeyStore().setKeyEntry(alias, secureKey, getChars(password), chain);
    } catch (Exception e) {
      throw new IllegalStateException("Failed to set Key with alias " + alias + " to KeyStore of type " + this.config.getType() + " at "
          + this.config.getResource().getUri() + "!", e);
    }
  }

  @Override
  public void save() {

    if (this.keyStore == null) {
      return;
    }
    CryptoResource resource = this.config.getResource();
    String type = this.config.getType();
    OutputStream outputStream = resource.openOutputStream();
    try {
      if (outputStream == null) { // for KeyStores of OS or specific hardware (PKCS11)
        this.keyStore.store(null, this.password);
      } else {
        try (OutputStream out = outputStream) {
          this.keyStore.store(out, this.password);
        }
      }
    } catch (Exception e) {
      throw new IllegalStateException("Failed to save KeyStore of type " + type + " to " + resource.getUri() + "!", e);
    }
  }

  @Override
  public String toString() {

    return this.config.getType() + "-KeyStore@" + this.config.getResource().getUri();
  }

}
