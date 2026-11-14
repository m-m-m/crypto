package io.github.mmm.crypto.key.store.access;

import java.io.File;

import io.github.mmm.crypto.io.CryptoFileResource;
import io.github.mmm.crypto.io.CryptoResource;
import io.github.mmm.crypto.key.store.KeyStoreConfigPkcs12;

/// [KeyStoreAccess] for [PKCS#12][KeyStoreConfigPkcs12].
///
/// @since 1.0.0
public class KeyStoreAccessPkcs12 extends KeyStoreAccess {

  /// The constructor.
  ///
  /// @param config the [KeyStoreConfigPkcs12].
  public KeyStoreAccessPkcs12(KeyStoreConfigPkcs12 config) {

    super(config);
  }

  /// @param keyStore the [File] pointing to the keystore.
  /// @param password the password used to encrypt/decrypt the keystore.
  /// @return the new instance.
  public static KeyStoreAccessPkcs12 of(File keyStore, String password) {

    return of(new CryptoFileResource(keyStore), password);
  }

  /// @param keyStoreResource the [CryptoResource] pointing to the keystore.
  /// @param password the password used to encrypt/decrypt the keystore.
  /// @return the new instance.
  public static KeyStoreAccessPkcs12 of(CryptoResource keyStoreResource, String password) {

    return new KeyStoreAccessPkcs12(new KeyStoreConfigPkcs12(keyStoreResource, password));
  }

}
