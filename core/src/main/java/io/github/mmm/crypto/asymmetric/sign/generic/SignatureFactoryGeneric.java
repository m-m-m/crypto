package io.github.mmm.crypto.asymmetric.sign.generic;

import io.github.mmm.crypto.asymmetric.sign.SignatureFactory;

/**
 * Implementation of {@link SignatureFactory} for {@link SignatureGeneric}.
 *
 * @since 1.0.0
 */
public class SignatureFactoryGeneric implements SignatureFactory<SignatureGeneric> {

  /** The singleton instance. */
  public static final SignatureFactoryGeneric INSTANCE = new SignatureFactoryGeneric();

  @Override
  public SignatureGeneric createSignature(byte[] data) {

    return new SignatureGeneric(data);
  }

}
