package net.sf.mmm.security.api.asymmetric.crypt;

import java.security.PrivateKey;
import java.security.PublicKey;

import net.sf.mmm.security.api.crypt.SecurityCryptorFactoryImpl;
import net.sf.mmm.security.api.random.SecurityRandomFactory;

/**
 * Implementation of {@link SecurityAsymmetricCryptorFactory}.
 *
 * @param <PR> type of {@link PrivateKey}.
 * @param <PU> type of {@link PublicKey}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityAsymmetricCryptorFactoryImpl<PR extends PrivateKey, PU extends PublicKey> extends SecurityCryptorFactoryImpl
    implements SecurityAsymmetricCryptorFactory<PR, PU> {

  private final SecurityAsymmetricCryptorConfig<PR, PU> config;

  /**
   * The constructor.
   *
   * @param config the {@link SecurityAsymmetricCryptorConfig}.
   * @param randomFactory the {@link SecurityRandomFactory}.
   */
  public SecurityAsymmetricCryptorFactoryImpl(SecurityAsymmetricCryptorConfig<PR, PU> config, SecurityRandomFactory randomFactory) {

    super(config.getProvider(), randomFactory);
    this.config = config;
  }

  @Override
  public SecurityAsymmetricCryptorConfig<PR, PU> getConfig() {

    return this.config;
  }

}
