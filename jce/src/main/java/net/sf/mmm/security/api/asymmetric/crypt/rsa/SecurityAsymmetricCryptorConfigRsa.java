package net.sf.mmm.security.api.asymmetric.crypt.rsa;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmRsa;
import net.sf.mmm.security.api.asymmetric.crypt.SecurityAsymmetricCryptorConfig;
import net.sf.mmm.security.api.crypt.SecurityCipherTransformation;
import net.sf.mmm.security.api.provider.SecurityProvider;

/**
 * {@link SecurityAsymmetricCryptorConfig} for {@link SecurityAlgorithmRsa RSA}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public final class SecurityAsymmetricCryptorConfigRsa extends SecurityAsymmetricCryptorConfig<RSAPrivateKey, RSAPublicKey>
    implements SecurityAlgorithmRsa {

  /** The signleton instance. */
  public static final SecurityAsymmetricCryptorConfigRsa RSA = new SecurityAsymmetricCryptorConfigRsa();

  /**
   * The constructor.
   */
  public SecurityAsymmetricCryptorConfigRsa() {

    this(null);
  }

  /**
   * The constructor.
   *
   * @param provider the {@link SecurityProvider}.
   */
  public SecurityAsymmetricCryptorConfigRsa(SecurityProvider provider) {

    super(new SecurityCipherTransformation(ALGORITHM_RSA), 0, provider);
  }

  @Override
  public boolean isBidirectional() {

    return true;
  }

}
