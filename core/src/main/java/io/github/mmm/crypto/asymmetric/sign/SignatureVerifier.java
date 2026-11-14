package io.github.mmm.crypto.asymmetric.sign;

import io.github.mmm.crypto.CryptoBinary;
import io.github.mmm.crypto.hash.Hash;

/// Extends [SignatureProcessor] with ability to [verify][#verify(CryptoBinary, SignatureBinary)] a message with a given expected signature.
///
/// @param <S> type of [SignatureBinary].
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public interface SignatureVerifier<S extends SignatureBinary> extends SignatureVerifierSimple {

  /// @param signature the `byte` array with the signature as raw data.
  /// @return `true` if the given signature is valid, `false` otherwise.
  default boolean verifyAfterUpdate(S signature) {

    return verifyAfterUpdate(signature.getData());
  }

  /// @param input the message data for which the `signature` was created.
  /// @param offset the index where to start reading data from `input`.
  /// @param length the number of bytes to read from `input`.
  /// @param signature the `byte` array with the signature as raw data.
  /// @return `true` if the given signature is valid, `false` otherwise.
  default boolean verify(byte[] input, int offset, int length, S signature) {

    update(input, offset, length);
    return verifyAfterUpdate(signature);
  }

  /// @param input the message data for which the `signature` was created.
  /// @param signature the `byte` array with the signature as raw data.
  /// @return `true` if the given signature is valid, `false` otherwise.
  default boolean verify(byte[] input, S signature) {

    update(input);
    return verifyAfterUpdate(signature);
  }

  /// @param input the message data for which the `signature` was created.
  /// @param signature the `byte` array with the signature as raw data.
  /// @return `true` if the given signature is valid, `false` otherwise.
  @SuppressWarnings("unchecked")
  default boolean verifyUnsafe(byte[] input, SignatureBinary signature) {

    return verify(input, (S) signature);
  }

  /// @param input the message data for which the `signature` was created. E.g. a [Hash].
  /// @param signature the `byte` array with the signature as raw data.
  /// @return `true` if the given signature is valid, `false` otherwise.
  default boolean verify(CryptoBinary input, S signature) {

    update(input);
    return verifyAfterUpdate(signature);
  }

}
