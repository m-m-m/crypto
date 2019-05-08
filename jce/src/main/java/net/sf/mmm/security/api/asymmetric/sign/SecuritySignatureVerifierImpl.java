package net.sf.mmm.security.api.asymmetric.sign;

import java.security.Signature;
import java.security.SignatureException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of {@link SecuritySignatureVerifier}.
 *
 * @param <S> type of {@link SecuritySignature}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecuritySignatureVerifierImpl<S extends SecuritySignature> extends SecuritySignatureProcessorImpl
    implements SecuritySignatureVerifier<S> {

  /** Logger instance. */
  private static final Logger LOG = LoggerFactory.getLogger(SecuritySignatureVerifierImpl.class);

  /**
   * The constructor.
   *
   * @param signature the underlying {@link Signature}.
   */
  public SecuritySignatureVerifierImpl(Signature signature) {

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
