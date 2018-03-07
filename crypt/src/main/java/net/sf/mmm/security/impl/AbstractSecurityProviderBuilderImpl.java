package net.sf.mmm.security.impl;

import java.security.Provider;
import java.security.Security;

import net.sf.mmm.security.api.provider.SecurityProviderBuilder;

/**
 * Implementation of {@link SecurityProviderBuilder}.
 *
 * @param <B> type of the returned builder.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface AbstractSecurityProviderBuilderImpl<B> extends SecurityProviderBuilder<B> {

  @Override
  default B provider() {

    return provider((Provider) null);
  }

  @Override
  default B provider(String name) {

    return provider(Security.getProvider(name));
  }

}
