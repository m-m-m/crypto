package io.github.mmm.crypto.key.store;

import io.github.mmm.crypto.io.CryptoResource;

/// [KeyStoreConfig] with [type][#getType()] "PKCS12" (Public-Key Cryptography Standards #12). For
/// details see <a href="https://en.wikipedia.org/wiki/PKCS_12">PKCS#12</a>. PKCS#12 is a quite complex and generic
/// format. It allows to define the encryption via an "AlgorithmIdentifier" so
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public class KeyStoreConfigPkcs12 extends KeyStoreConfig {

  /// The [type][#getType()] {@value}.
  public static final String TYPE = "PKCS12";

  /// The constructor.
  ///
  /// @param resource the [resource][#getResource()].
  /// @param password the [password][#getPassword()].
  public KeyStoreConfigPkcs12(CryptoResource resource, String password) {
    super(TYPE, resource, password);
  }

  @Override
  public String getExtension() {

    return ".p12";
  }

}
