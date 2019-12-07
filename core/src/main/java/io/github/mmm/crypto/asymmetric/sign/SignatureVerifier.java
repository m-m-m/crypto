package io.github.mmm.crypto.asymmetric.sign;

import io.github.mmm.crypto.CryptoBinary;
import io.github.mmm.crypto.hash.Hash;

/**
 * Extends {@link SignatureProcessor} with ability to {@link #verify(CryptoBinary, SignatureBinary)
 * verify} a message with a given expected signature.
 *
 * @param <S> type of {@link SignatureBinary}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SignatureVerifier<S extends SignatureBinary> extends SignatureVerifierSimple {

  /**
   * @param signature the {@code byte} array with the signature as raw data.
   * @return {@code true} if the given signature is valid, {@code false} otherwise.
   */
  default boolean verifyAfterUpdate(S signature) {

    return verifyAfterUpdate(signature.getData());
  }

  /**
   * @param input the message data for which the {@code signature} was created.
   * @param offset the index where to start reading data from {@code input}.
   * @param length the number of bytes to read from {@code input}.
   * @param signature the {@code byte} array with the signature as raw data.
   * @return {@code true} if the given signature is valid, {@code false} otherwise.
   */
  default boolean verify(byte[] input, int offset, int length, S signature) {

    update(input, offset, length);
    return verifyAfterUpdate(signature);
  }

  /**
   * @param input the message data for which the {@code signature} was created.
   * @param signature the {@code byte} array with the signature as raw data.
   * @return {@code true} if the given signature is valid, {@code false} otherwise.
   */
  default boolean verify(byte[] input, S signature) {

    update(input);
    return verifyAfterUpdate(signature);
  }

  /**
   * @param input the message data for which the {@code signature} was created.
   * @param signature the {@code byte} array with the signature as raw data.
   * @return {@code true} if the given signature is valid, {@code false} otherwise.
   */
  @SuppressWarnings("unchecked")
  default boolean verifyUnsafe(byte[] input, SignatureBinary signature) {

    return verify(input, (S) signature);
  }

  /**
   * @param input the message data for which the {@code signature} was created. E.g. a {@link Hash}.
   * @param signature the {@code byte} array with the signature as raw data.
   * @return {@code true} if the given signature is valid, {@code false} otherwise.
   */
  default boolean verify(CryptoBinary input, S signature) {

    update(input);
    return verifyAfterUpdate(signature);
  }

}
