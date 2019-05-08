package net.sf.mmm.security.api.asymmetric.sign;

/**
 * Extends {@link SecuritySignatureProcessor} with ability to {@link #signAfterUpdateRaw(boolean) sign} the
 * {@link #update(byte[]) processed data} generating a signature.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecuritySignatureSignerSimple extends SecuritySignatureProcessor {

  /**
   * @param reset - {@code true} to {@link #reset() reset} after the signature has been generated, {@code false}
   *        otherwise.
   * @return the final signature generated for the {@link #update(byte[]) processed data}.
   */
  byte[] signAfterUpdateRaw(boolean reset);

  @Override
  default byte[] process(byte[] input, int offset, int length, boolean complete) {

    update(input, offset, length);
    return signAfterUpdateRaw(complete);
  }

}
