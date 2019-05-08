package net.sf.mmm.security.api.crypt;

/**
 * Extends {@link AbstractSecurityGetCryptorFactory} with ability to {@link #setCryptorFactory(SecurityCryptorFactory)
 * set} the {@link SecurityCryptorFactory}.
 *
 * @param <C> the type of the {@link SecurityCryptorFactory}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract interface AbstractSecuritySetCryptorFactory<C extends SecurityCryptorFactory>
    extends AbstractSecurityGetCryptorFactory<C> {

  /**
   * @param factory the {@link SecurityCryptorFactory} to set.
   */
  void setCryptorFactory(C factory);

}
