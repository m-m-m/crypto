package io.github.mmm.crypto.algorithm;

import java.security.Provider;

import io.github.mmm.crypto.provider.SecurityProvider;

/// The abstract base implementation of [CryptoAlgorithm].
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public abstract class AbstractCryptoAlgorithmWithProvider extends AbstractSecurityAlgorithm {

  /// The [SecurityProvider].
  protected final SecurityProvider provider;

  /// The constructor.
  ///
  /// @param provider the optional security [Provider].
  public AbstractCryptoAlgorithmWithProvider(SecurityProvider provider) {

    super();
    if (provider == null) {
      this.provider = SecurityProvider.DEFAULT;
    } else {
      this.provider = provider;
    }
  }

  /// @return the [SecurityProvider].
  public SecurityProvider getProvider() {

    return this.provider;
  }

}
