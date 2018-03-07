package net.sf.mmm.security.api.key.symmetric;

/**
 * Extends {@link AbstractSecurityGetSymmetricKeyFactory} with ability to
 * {@link #setSymmetricKeyFactory(SecuritySymmetricKeyFactory) set} the {@link SecuritySymmetricKeyFactory}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface AbstractSecuritySetSymmetricKeyFactory extends AbstractSecurityGetSymmetricKeyFactory {

  /**
   * @param factory the {@link SecuritySymmetricKeyFactory} to set.
   */
  void setSymmetricKeyFactory(SecuritySymmetricKeyFactory factory);

}
