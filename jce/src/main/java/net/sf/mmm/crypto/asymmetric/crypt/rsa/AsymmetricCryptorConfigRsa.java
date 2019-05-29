package net.sf.mmm.crypto.asymmetric.crypt.rsa;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import net.sf.mmm.crypto.asymmetric.crypt.AsymmetricCryptorConfig;
import net.sf.mmm.crypto.asymmetric.key.rsa.AsymmetricKeyPairRsa;
import net.sf.mmm.crypto.crypt.CipherTransformation;
import net.sf.mmm.crypto.provider.SecurityProvider;

/**
 * {@link AsymmetricCryptorConfig} for {@link net.sf.mmm.crypto.asymmetric.access.rsa.Rsa}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public final class AsymmetricCryptorConfigRsa extends AsymmetricCryptorConfig<RSAPrivateKey, RSAPublicKey> {

  /** The signleton instance. */
  public static final AsymmetricCryptorConfigRsa RSA = new AsymmetricCryptorConfigRsa();

  /**
   * The constructor.
   */
  public AsymmetricCryptorConfigRsa() {

    this(null);
  }

  /**
   * The constructor.
   *
   * @param provider the {@link SecurityProvider}.
   */
  public AsymmetricCryptorConfigRsa(SecurityProvider provider) {

    super(new CipherTransformation(AsymmetricKeyPairRsa.ALGORITHM_RSA), 0, provider);
  }

  @Override
  public boolean isBidirectional() {

    return true;
  }

}
