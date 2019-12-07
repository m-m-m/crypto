package io.github.mmm.crypto.asymmetric.crypt.rsa;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import io.github.mmm.crypto.asymmetric.crypt.AsymmetricCryptorConfig;
import io.github.mmm.crypto.asymmetric.key.rsa.AsymmetricKeyPairRsa;
import io.github.mmm.crypto.crypt.CipherTransformation;
import io.github.mmm.crypto.provider.SecurityProvider;

/**
 * {@link AsymmetricCryptorConfig} for {@link io.github.mmm.crypto.asymmetric.access.rsa.Rsa}.
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
