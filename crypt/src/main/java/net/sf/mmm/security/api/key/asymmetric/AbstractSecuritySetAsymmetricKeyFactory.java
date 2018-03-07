package net.sf.mmm.security.api.key.asymmetric;

/**
 * Extends {@link AbstractSecurityGetAsymmetricKeyFactory} with ability to
 * {@link #setAsymmetricKeyFactory(SecurityAsymmetricKeyFactory) set} the {@link SecurityAsymmetricKeyFactory}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface AbstractSecuritySetAsymmetricKeyFactory extends AbstractSecurityGetAsymmetricKeyFactory {

  /**
   * @param factory the {@link SecurityAsymmetricKeyFactory} to set.
   */
  void setAsymmetricKeyFactory(SecurityAsymmetricKeyFactory factory);

}
