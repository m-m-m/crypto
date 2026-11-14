package io.github.mmm.crypto.key.store.bc;

import io.github.mmm.crypto.io.CryptoResource;
import io.github.mmm.crypto.key.store.KeyStoreConfig;
import io.github.mmm.crypto.provider.SecurityProvider;
import io.github.mmm.crypto.provider.bc.BouncyCastle;

/// [KeyStoreConfig] with [type][#getType()] "BKS" (Bouncycaste KeyStore). This is a proprietary format from
/// the popular third party Java cryptographic library provider <a href="https://bouncycastle.org/">BouncyCastle</a>.
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public class KeyStoreConfigBks extends KeyStoreConfig {

  /// The [type][#getType()] {@value}.
  public static final String TYPE = "BKS";

  /// The constructor.
  ///
  /// @param resource the [resource][#getResource()].
  /// @param password the [password][#getPassword()].
  public KeyStoreConfigBks(CryptoResource resource, String password) {

    super(TYPE, SecurityProvider.of(BouncyCastle.getProvider()), resource, password);
  }

}
