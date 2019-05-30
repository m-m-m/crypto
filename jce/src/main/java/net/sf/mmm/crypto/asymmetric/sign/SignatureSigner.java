package net.sf.mmm.crypto.asymmetric.sign;

import net.sf.mmm.crypto.CryptoBinary;
import net.sf.mmm.crypto.hash.Hash;

/**
 * Extends {@link SignatureProcessor} with ability to {@link #signAfterUpdate(boolean) sign} the
 * {@link #update(byte[]) processed data} generating a signature.
 *
 * @param <S> type of {@link SignatureBinary}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SignatureSigner<S extends SignatureBinary> extends SignatureSignerSimple {

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
   * @param input the {@link CryptoBinary} containing the (next) {@link CryptoBinary#getData() data} to
   *        sign. E.g. a {@link Hash}.
   * @param reset - {@code true} to {@link #reset() reset} after the signature has been generated, {@code false}
   *        otherwise.
   * @return the final signature generated for the {@link #update(byte[]) processed data}.
   */
  default S sign(CryptoBinary input, boolean reset) {

    update(input);
    return signAfterUpdate(reset);
  }

}
