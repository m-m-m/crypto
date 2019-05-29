package net.sf.mmm.crypto.asymmetric.crypt;

import java.security.PrivateKey;
import java.security.PublicKey;

import net.sf.mmm.crypto.crypt.CryptorFactoryImpl;
import net.sf.mmm.crypto.random.RandomFactory;

/**
 * Implementation of {@link AsymmetricCryptorFactory}.
 *
 * @param <PR> type of {@link PrivateKey}.
 * @param <PU> type of {@link PublicKey}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class AsymmetricCryptorFactoryImpl<PR extends PrivateKey, PU extends PublicKey> extends CryptorFactoryImpl
    implements AsymmetricCryptorFactory<PR, PU> {

  private final AsymmetricCryptorConfig<PR, PU> config;

  /**
   * The constructor.
   *
   * @param config the {@link AsymmetricCryptorConfig}.
   * @param randomFactory the {@link RandomFactory}.
   */
  public AsymmetricCryptorFactoryImpl(AsymmetricCryptorConfig<PR, PU> config, RandomFactory randomFactory) {

    super(config.getProvider(), randomFactory);
    this.config = config;
  }

  @Override
  public AsymmetricCryptorConfig<PR, PU> getConfig() {

    return this.config;
  }

}
