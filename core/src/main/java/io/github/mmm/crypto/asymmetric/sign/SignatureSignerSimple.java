package io.github.mmm.crypto.asymmetric.sign;

/// Extends [SignatureProcessor] with ability to [sign][#signAfterUpdateRaw(boolean)] the
/// [processed data][#update(byte[])] generating a signature.
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public interface SignatureSignerSimple extends SignatureProcessor {

  /// @param reset - `true` to [reset][#reset()] after the signature has been generated, `false`
  ///        otherwise.
  /// @return the final signature generated for the [processed data][#update(byte[])].
  byte[] signAfterUpdateRaw(boolean reset);

  @Override
  default byte[] process(byte[] input, int offset, int length, boolean complete) {

    update(input, offset, length);
    return signAfterUpdateRaw(complete);
  }

}
