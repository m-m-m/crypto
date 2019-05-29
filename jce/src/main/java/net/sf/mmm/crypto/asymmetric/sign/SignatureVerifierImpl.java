package net.sf.mmm.crypto.asymmetric.sign;

import java.security.Signature;
import java.security.SignatureException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of {@link SignatureVerifier}.
 *
 * @param <S> type of {@link SignatureBinary}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SignatureVerifierImpl<S extends SignatureBinary> extends SignatureProcessorImpl
    implements SignatureVerifier<S> {

  /** Logger instance. */
  private static final Logger LOG = LoggerFactory.getLogger(SignatureVerifierImpl.class);

  /**
   * The constructor.
   *
   * @param signature the underlying {@link Signature}.
   */
  public SignatureVerifierImpl(Signature signature) {

    super(signature);
  }

  @Override
  public boolean verifyAfterUpdate(byte[] signature, int offset, int length) {

    try {
      return getSignature().verify(signature, offset, length);
    } catch (SignatureException e) {
      LOG.warn("Error whilst verifying signature.", e);
      return false;
    }
  }

}
