package net.sf.mmm.security.api.sign;

/**
 * Extends {@link SecuritySignatureCreator} with ability to {@link #verify(byte[], byte[]) verify} a message with a
 * given expected signature.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecuritySignatureVerifier extends SecuritySignatureCreator {

  /**
   * @param signature the {@code byte} array with the signature as raw data.
   * @return {@code true} if the given signature is valid, {@code false} otherwise.
   */
  default boolean verifyAfterUpdate(byte[] signature) {

    return verifyAfterUpdate(signature, 0, signature.length);
  }

  /**
   * @param signature the {@code byte} array with the signature as raw data.
   * @param offset the index where to start reading data from {@code signature}.
   * @param length the number of bytes to read from {@code signature}.
   * @return {@code true} if the given signature is valid, {@code false} otherwise.
   */
  boolean verifyAfterUpdate(byte[] signature, int offset, int length);

  /**
   * @param signature the {@code byte} array with the signature as raw data.
   * @return {@code true} if the given signature is valid, {@code false} otherwise.
   */
  default boolean verifyAfterUpdate(SecuritySignature signature) {

    return verifyAfterUpdate(signature.getData());
  }

  /**
   * @param input the message data for which the {@code signature} was created.
   * @param signature the {@code byte} array with the signature as raw data.
   * @return {@code true} if the given signature is valid, {@code false} otherwise.
   */
  default boolean verify(byte[] input, byte[] signature) {

    update(input);
    return verifyAfterUpdate(signature);
  }

  /**
   * @param input the message data for which the {@code signature} was created.
   * @param signature the {@code byte} array with the signature as raw data.
   * @param signatureOffset the index where to start reading data from {@code signature}.
   * @param signatureLength the number of bytes to read from {@code signature}.
   * @return {@code true} if the given signature is valid, {@code false} otherwise.
   */
  default boolean verify(byte[] input, byte[] signature, int signatureOffset, int signatureLength) {

    update(input);
    return verifyAfterUpdate(signature, signatureOffset, signatureLength);
  }

  /**
   * @param input the message data for which the {@code signature} was created.
   * @param inputOffset the index where to start reading data from {@code input}.
   * @param inputLength the number of bytes to read from {@code input}.
   * @param signature the {@code byte} array with the signature as raw data.
   * @param signatureOffset the index where to start reading data from {@code signature}.
   * @param signatureLength the number of bytes to read from {@code signature}.
   * @return {@code true} if the given signature is valid, {@code false} otherwise.
   */
  default boolean verify(byte[] input, int inputOffset, int inputLength, byte[] signature, int signatureOffset,
      int signatureLength) {

    update(input, inputOffset, inputLength);
    return verifyAfterUpdate(signature, signatureOffset, signatureLength);
  }

  /**
   * @param input the message data for which the {@code signature} was created.
   * @param offset the index where to start reading data from {@code input}.
   * @param length the number of bytes to read from {@code input}.
   * @param signature the {@code byte} array with the signature as raw data.
   * @return {@code true} if the given signature is valid, {@code false} otherwise.
   */
  default boolean verify(byte[] input, int offset, int length, SecuritySignature signature) {

    update(input, offset, length);
    return verifyAfterUpdate(signature);
  }

  /**
   * @param input the message data for which the {@code signature} was created.
   * @param signature the {@code byte} array with the signature as raw data.
   * @return {@code true} if the given signature is valid, {@code false} otherwise.
   */
  default boolean verify(byte[] input, SecuritySignature signature) {

    update(input);
    return verifyAfterUpdate(signature);
  }

}
