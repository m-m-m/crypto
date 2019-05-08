package net.sf.mmm.security.api.asymmetric.sign;

import net.sf.mmm.security.api.SecurityBinaryType;
import net.sf.mmm.security.api.hash.SecurityHash;

/**
 * Extends {@link SecuritySignatureProcessor} with ability to {@link #signAfterUpdate(boolean) sign} the
 * {@link #update(byte[]) processed data} generating a signature.
 *
 * @param <S> type of {@link SecuritySignature}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecuritySignatureSigner<S extends SecuritySignature> extends SecuritySignatureSignerSimple {

  /**
   * @param reset - {@code true} to {@link #reset() reset} after the signature has been generated, {@code false}
   *        otherwise.
   * @return the final signature generated for the {@link #update(byte[]) processed data}.
   */
  S signAfterUpdate(boolean reset);

  /**
   * @param input the data to sign.
   * @param reset - {@code true} to {@link #reset() reset} after the signature has been generated, {@code false}
   *        otherwise.
   * @return the final signature generated for the {@link #update(byte[]) processed data}.
   */
  default S sign(byte[] input, boolean reset) {

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
  default S sign(byte[] input, int offset, int length, boolean reset) {

    update(input, offset, length);
    return signAfterUpdate(reset);
  }

  /**
   * @param input the {@link SecurityBinaryType} containing the (next) {@link SecurityBinaryType#getData() data} to
   *        sign. E.g. a {@link SecurityHash}.
   * @param reset - {@code true} to {@link #reset() reset} after the signature has been generated, {@code false}
   *        otherwise.
   * @return the final signature generated for the {@link #update(byte[]) processed data}.
   */
  default S sign(SecurityBinaryType input, boolean reset) {

    update(input);
    return signAfterUpdate(reset);
  }

}
