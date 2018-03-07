package net.sf.mmm.security.impl.key.symmetric;

import java.security.Provider;

import net.sf.mmm.security.api.key.symmetric.SecuritySymmetricKeyConfig;
import net.sf.mmm.security.api.key.symmetric.SecuritySymmetricKeyCreator;
import net.sf.mmm.security.api.key.symmetric.SecuritySymmetricKeyFactory;
import net.sf.mmm.security.impl.AbstractSecurityAlgorithmWithProvider;

/**
 * Implementation of {@link SecuritySymmetricKeyFactory}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecuritySymmetricKeyFactoryImpl extends AbstractSecurityAlgorithmWithProvider
    implements SecuritySymmetricKeyFactory {

  private final SecuritySymmetricKeyConfig config;

  /**
   * The constructor.
   *
   * @param config the {@link SecuritySymmetricKeyConfig}.
   * @param provider the security {@link Provider}.
   */
  public SecuritySymmetricKeyFactoryImpl(SecuritySymmetricKeyConfig config, Provider provider) {
    super(provider);
    this.config = config;
  }

  @Override
  public String getAlgorithm() {

    return this.config.getAlgorithm();
  }

  @Override
  public SecuritySymmetricKeyCreator newKeyCreator() {

    return new SecuritySymmetricKeyCreatorImpl(this.config, getProvider());
  }

}
