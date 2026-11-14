package io.github.mmm.crypto.asymmetric.sign;

/// Interface for factory to create instances of [SignatureBinary]. It is only relevant for internal usage and as
/// SPI. End-users should look at [SignatureProcessorFactory].
///
/// @param <S> type of [SignatureBinary].
/// @since 1.0.0
public interface SignatureFactory<S extends SignatureBinary> {

  /// @param data the [binary signature data][SignatureBinary#getData()].
  /// @return the deserialized [SignatureBinary].
  S createSignature(byte[] data);

}
