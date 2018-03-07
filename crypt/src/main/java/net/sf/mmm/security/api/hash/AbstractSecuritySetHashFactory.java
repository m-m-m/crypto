package net.sf.mmm.security.api.hash;

import net.sf.mmm.security.api.crypt.AbstractSecurityGetCryptorFactory;

/**
 * Extends {@link AbstractSecurityGetCryptorFactory} with ability to {@link #setHashFactory(SecurityHashFactory) set}
 * the {@link SecurityHashFactory}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface AbstractSecuritySetHashFactory extends AbstractSecurityGetHashFactory {

  /**
   * @param factory the {@link SecurityHashFactory} to set.
   */
  void setHashFactory(SecurityHashFactory factory);

}
