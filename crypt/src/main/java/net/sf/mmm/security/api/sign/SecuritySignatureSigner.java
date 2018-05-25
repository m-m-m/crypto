package net.sf.mmm.security.api.sign;

import net.sf.mmm.security.api.SecurityBinaryType;
import net.sf.mmm.security.api.hash.SecurityHash;

/**
 * Extends {@link SecuritySignatureCreator} with ability to {@link #sign(boolean) sign} the {@link #update(byte[])
 * processed data} generating a signature.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecuritySignatureSigner extends SecuritySignatureCreator {

  /**
   * @param reset - {@code true} to {@link #reset() reset} after the signature has been generated, {@code false}
   *        otherwise.
   * @return the final signature generated for the {@link #update(byte[]) processed data}.
   */
  byte[] sign(boolean reset);

  /**
   * @param input the data to sign.
   * @param reset - {@code true} to {@link #reset() reset} after the signature has been generated, {@code false}
   *        otherwise.
   * @return the final signature generated for the {@link #update(byte[]) processed data}.
   */
  default byte[] sign(byte[] input, boolean reset) {

    return sign(input, 0, input.length, reset);
  }

  /**
   * @param input the data to sign.
   * @param offset the index where to start reading data from {@code input}.
   * @param length the number of bytes to read from {@code input}.
   * @param reset - {@code true} to {@link #reset() reset} after the signature has been generated, {@code false}
   *        otherwise.
   * @return the final signature generated for the {@link #update(byte[]) processed data}.
   */
  default byte[] sign(byte[] input, int offset, int length, boolean reset) {

    update(input, offset, length);
    return sign(reset);
  }

  @Override
  default byte[] process(byte[] input, int offset, int length, boolean complete) {

    return sign(input, offset, length, complete);
  }

  /**
   * @param input the {@link SecurityBinaryType} containing the (next) {@link SecurityBinaryType#getData() data} to
   *        sign. E.g. a {@link SecurityHash}.
   * @param reset - {@code true} to {@link #reset() reset} after the signature has been generated, {@code false}
   *        otherwise.
   * @return the final signature generated for the {@link #update(byte[]) processed data}.
   */
  default SecuritySignature signature(SecurityBinaryType input, boolean reset) {

    update(input);
    return new SecuritySignature(sign(reset));
  }

  /**
   * @param reset - {@code true} to {@link #reset() reset} after the signature has been generated, {@code false}
   *        otherwise.
   * @return the final signature generated for the {@link #update(byte[]) processed data}.
   */
  default SecuritySignature signature(boolean reset) {

    return new SecuritySignature(sign(reset));
  }

}
