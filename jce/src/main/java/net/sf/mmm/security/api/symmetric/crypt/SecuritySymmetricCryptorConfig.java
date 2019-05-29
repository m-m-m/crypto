package net.sf.mmm.security.api.symmetric.crypt;

import net.sf.mmm.security.api.crypt.SecurityCipherTransformation;
import net.sf.mmm.security.api.crypt.SecurityCryptorConfig;
import net.sf.mmm.security.api.provider.SecurityProvider;

/**
 * {@link SecurityCryptorConfig} for {@link SecuritySymmetricCryptorFactory symmetric encryption}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecuritySymmetricCryptorConfig extends SecurityCryptorConfig {

  /**
   * The constructor.
   *
   * @param transformation the {@link #getTransformation() transfomation} for the {@link javax.crypto.Cipher}.
   * @param nonceSize the {@link #getNonceSize() nonce size}.
   * @param provider the {@link SecurityProvider}.
   */
  public SecuritySymmetricCryptorConfig(SecurityCipherTransformation transformation, SecurityProvider provider, int nonceSize) {

    super(transformation, provider, nonceSize);
  }

}
