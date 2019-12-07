package io.github.mmm.crypto.asymmetric.sign;

/**
 * Interface for factory to create instances of {@link SignatureBinary}. It is only relevant for internal usage and as
 * SPI. End-users should look at {@link SignatureProcessorFactory}.
 *
 * @param <S> type of {@link SignatureBinary}.
 * @since 1.0.0
 */
public interface SignatureFactory<S extends SignatureBinary> {

  /**
   * @param data the {@link SignatureBinary#getData() binary signature data}.
   * @return the deserialized {@link SignatureBinary}.
   */
  S createSignature(byte[] data);

}
