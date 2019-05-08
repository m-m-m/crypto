package net.sf.mmm.security.api.asymmetric.sign;

import net.sf.mmm.security.api.SecurityBinaryType;
import net.sf.mmm.security.api.hash.SecurityHash;

/**
 * Extends {@link SecuritySignatureProcessor} with ability to {@link #verify(SecurityBinaryType, SecuritySignature)
 * verify} a message with a given expected signature.
 *
 * @param <S> type of {@link SecuritySignature}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecuritySignatureVerifier<S extends SecuritySignature> extends SecuritySignatureVerifierSimple {

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
  default boolean verifyUnsafe(byte[] input, SecuritySignature signature) {

    return verify(input, (S) signature);
  }

  /**
   * @param input the message data for which the {@code signature} was created. E.g. a {@link SecurityHash}.
   * @param signature the {@code byte} array with the signature as raw data.
   * @return {@code true} if the given signature is valid, {@code false} otherwise.
   */
  default boolean verify(SecurityBinaryType input, S signature) {

    update(input);
    return verifyAfterUpdate(signature);
  }

}
