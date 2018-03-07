package net.sf.mmm.security.impl;

import net.sf.mmm.security.api.AbstractSecurityBuilder;
import net.sf.mmm.security.api.SecurityBuilder;
import net.sf.mmm.security.api.SecurityFactoryBuilder;

/**
 * Implementation of {@link SecurityBuilder}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityBuilderImpl extends AbstractSecurityBuilder {

  /**
   * The constructor.
   */
  public SecurityBuilderImpl() {

    super();
    UnlimitedKeyStrengthJurisdictionPolicy.ensure();
  }

  @Override
  public SecurityFactoryBuilder newFactoryBuilder() {

    return new SecurityFactoryBuilderImpl();
  }

}
