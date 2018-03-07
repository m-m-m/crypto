package net.sf.mmm.security.api.key.store;

/**
 * Extends {@link AbstractSecurityGetKeyStore} with ability to {@link #setKeyStore(SecurityKeyStore) set} the
 * {@link SecurityKeyStore}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface AbstractSecuritySetKeyStore extends AbstractSecurityGetKeyStore {

  /**
   * @param factory the {@link SecurityKeyStore} to set.
   */
  void setKeyStore(SecurityKeyStore factory);

}
