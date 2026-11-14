package io.github.mmm.crypto.asymmetric.sign.rsa;

import io.github.mmm.crypto.asymmetric.sign.SignatureBinary;

/// [SignatureBinary] for [io.github.mmm.crypto.asymmetric.access.rsa.Rsa].
///
/// @since 1.0.0
public class SignatureRsa extends SignatureBinary {

  /// The constructor.
  ///
  /// @param data the raw binary [data][#getData()].
  public SignatureRsa(byte[] data) {

    super(data);
  }

}
