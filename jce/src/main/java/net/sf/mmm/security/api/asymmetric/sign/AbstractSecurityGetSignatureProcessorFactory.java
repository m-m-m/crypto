package net.sf.mmm.security.api.asymmetric.sign;

/**
 * Abstract interface to {@link #getSignatureFactory() get} the {@link SecuritySignatureProcessorFactory}.
 *
 * @param <S> type of {@link SecuritySignatureProcessorFactory}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract interface AbstractSecurityGetSignatureProcessorFactory<S extends SecuritySignatureProcessorFactory<?, ?, ?>> {

  /**
   * @return the {@link SecuritySignatureProcessorFactory}.
   */
  S getSignatureFactory();

}
