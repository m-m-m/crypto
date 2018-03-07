package net.sf.mmm.security.impl.sign;

import java.security.Signature;
import java.security.SignatureException;

import net.sf.mmm.security.api.sign.SecuritySignatureSigner;

/**
 * Implementation of {@link SecuritySignatureSigner}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecuritySignatureSignerImpl extends SecuritySignatureGeneratorImpl implements SecuritySignatureSigner {

  /**
   * The constructor.
   *
   * @param signature the underlying {@link Signature}.
   */
  public SecuritySignatureSignerImpl(Signature signature) {

    super(signature);
  }

  @Override
  public byte[] sign(boolean reset) {

    try {
      byte[] signature = getSignature().sign();
      if (reset) {
        reset();
      }
      return signature;
    } catch (SignatureException e) {
      throw creationFailedException(e, Signature.class);
    }
  }

}
