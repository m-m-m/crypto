package net.sf.mmm.security.api.asymmetric.sign;

/**
 * Extends {@link AbstractSecurityGetSignatureProcessorFactory} with ability to
 * {@link #setSignatureFactory(SecuritySignatureProcessorFactory) set} the {@link SecuritySignatureProcessorFactory}.
 *
 * @param <S> type of {@link SecuritySignatureProcessorFactory}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface AbstractSecuritySetSignatureProcessorFactory<S extends SecuritySignatureProcessorFactory<?, ?, ?>>
    extends AbstractSecurityGetSignatureProcessorFactory<S> {

  /**
   * @param factory the {@link SecuritySignatureProcessorFactory} to set.
   */
  void setSignatureFactory(S factory);

}
