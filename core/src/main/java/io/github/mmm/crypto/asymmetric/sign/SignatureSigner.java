package io.github.mmm.crypto.asymmetric.sign;

import io.github.mmm.crypto.CryptoBinary;
import io.github.mmm.crypto.hash.Hash;

/// Extends [SignatureProcessor] with ability to [sign][#signAfterUpdate(boolean)] the
/// [processed data][#update(byte[])] generating a signature.
///
/// @param <S> type of [SignatureBinary].
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public interface SignatureSigner<S extends SignatureBinary> extends SignatureSignerSimple {

  /// @param reset - `true` to [reset][#reset()] after the signature has been generated, `false`
  ///        otherwise.
  /// @return the final signature generated for the [processed data][#update(byte[])].
  S signAfterUpdate(boolean reset);

  /// @param input the data to sign.
  /// @param reset - `true` to [reset][#reset()] after the signature has been generated, `false`
  ///        otherwise.
  /// @return the final signature generated for the [processed data][#update(byte[])].
  default S sign(byte[] input, boolean reset) {

    return sign(input, 0, input.length, reset);
  }

  /// @param input the data to sign.
  /// @param offset the index where to start reading data from `input`.
  /// @param length the number of bytes to read from `input`.
  /// @param reset - `true` to [reset][#reset()] after the signature has been generated, `false`
  ///        otherwise.
  /// @return the final signature generated for the [processed data][#update(byte[])].
  default S sign(byte[] input, int offset, int length, boolean reset) {

    update(input, offset, length);
    return signAfterUpdate(reset);
  }

  /// @param input the [CryptoBinary] containing the (next) [data][CryptoBinary#getData()] to
  ///        sign. E.g. a [Hash].
  /// @param reset - `true` to [reset][#reset()] after the signature has been generated, `false`
  ///        otherwise.
  /// @return the final signature generated for the [processed data][#update(byte[])].
  default S sign(CryptoBinary input, boolean reset) {

    update(input);
    return signAfterUpdate(reset);
  }

}
