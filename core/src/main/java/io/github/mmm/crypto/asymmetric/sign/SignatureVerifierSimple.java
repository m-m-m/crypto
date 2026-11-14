package io.github.mmm.crypto.asymmetric.sign;

/// Extends [SignatureProcessor] with ability to [verify][#verify(byte[], byte[])] a message with a
/// given expected signature.
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public interface SignatureVerifierSimple extends SignatureProcessor {

  /// @param signature the `byte` array with the signature as raw data.
  /// @return `true` if the given signature is valid, `false` otherwise.
  default boolean verifyAfterUpdate(byte[] signature) {

    return verifyAfterUpdate(signature, 0, signature.length);
  }

  /// @param signature the `byte` array with the signature as raw data.
  /// @param offset the index where to start reading data from `signature`.
  /// @param length the number of bytes to read from `signature`.
  /// @return `true` if the given signature is valid, `false` otherwise.
  boolean verifyAfterUpdate(byte[] signature, int offset, int length);

  /// @param input the message data for which the `signature` was created.
  /// @param signature the `byte` array with the signature as raw data.
  /// @return `true` if the given signature is valid, `false` otherwise.
  default boolean verify(byte[] input, byte[] signature) {

    update(input);
    return verifyAfterUpdate(signature);
  }

  /// @param input the message data for which the `signature` was created.
  /// @param signature the `byte` array with the signature as raw data.
  /// @param signatureOffset the index where to start reading data from `signature`.
  /// @param signatureLength the number of bytes to read from `signature`.
  /// @return `true` if the given signature is valid, `false` otherwise.
  default boolean verify(byte[] input, byte[] signature, int signatureOffset, int signatureLength) {

    update(input);
    return verifyAfterUpdate(signature, signatureOffset, signatureLength);
  }

  /// @param input the message data for which the `signature` was created.
  /// @param inputOffset the index where to start reading data from `input`.
  /// @param inputLength the number of bytes to read from `input`.
  /// @param signature the `byte` array with the signature as raw data.
  /// @param signatureOffset the index where to start reading data from `signature`.
  /// @param signatureLength the number of bytes to read from `signature`.
  /// @return `true` if the given signature is valid, `false` otherwise.
  default boolean verify(byte[] input, int inputOffset, int inputLength, byte[] signature, int signatureOffset, int signatureLength) {

    update(input, inputOffset, inputLength);
    return verifyAfterUpdate(signature, signatureOffset, signatureLength);
  }

}
