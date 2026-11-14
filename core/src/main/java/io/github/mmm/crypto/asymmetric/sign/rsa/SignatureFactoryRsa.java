package io.github.mmm.crypto.asymmetric.sign.rsa;

import io.github.mmm.crypto.asymmetric.sign.SignatureFactory;

/// Implementation of [SignatureFactory] for [SignatureRsa].
///
/// @since 1.0.0
public class SignatureFactoryRsa implements SignatureFactory<SignatureRsa> {

  private static final SignatureFactoryRsa INSTANCE = new SignatureFactoryRsa();

  @Override
  public SignatureRsa createSignature(byte[] data) {

    return new SignatureRsa(data);
  }

  /// @return the singleton instance of [SignatureFactoryRsa].
  public static SignatureFactoryRsa get() {

    return INSTANCE;
  }

}
