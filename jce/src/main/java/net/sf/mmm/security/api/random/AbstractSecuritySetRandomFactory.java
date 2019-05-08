package net.sf.mmm.security.api.random;

/**
 * Extends {@link AbstractSecurityGetRandomFactory} with ability to {@link #setRandomFactory(SecurityRandomFactory) set}
 * the {@link SecurityRandomFactory}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface AbstractSecuritySetRandomFactory extends AbstractSecurityGetRandomFactory {

  /**
   * @param factory the {@link SecurityRandomFactory} to set.
   */
  void setRandomFactory(SecurityRandomFactory factory);

}
