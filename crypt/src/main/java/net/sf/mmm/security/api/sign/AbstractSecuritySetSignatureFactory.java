package net.sf.mmm.security.api.sign;

/**
 * Extends {@link AbstractSecurityGetSignatureFactory} with ability to
 * {@link #setSignatureFactory(SecuritySignatureFactory) set} the {@link SecuritySignatureFactory}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface AbstractSecuritySetSignatureFactory extends AbstractSecurityGetSignatureFactory {

  /**
   * @param factory the {@link SecuritySignatureFactory} to set.
   */
  void setSignatureFactory(SecuritySignatureFactory factory);

}
