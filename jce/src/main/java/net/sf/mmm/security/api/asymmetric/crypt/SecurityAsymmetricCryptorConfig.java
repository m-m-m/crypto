package net.sf.mmm.security.api.asymmetric.crypt;

import java.security.PrivateKey;
import java.security.PublicKey;

import net.sf.mmm.security.api.crypt.SecurityCipherTransformation;
import net.sf.mmm.security.api.crypt.SecurityCryptorConfig;
import net.sf.mmm.security.api.provider.SecurityProvider;

/**
 * {@link SecurityCryptorConfig} for {@link net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyPair asymmetric
 * cryptography}.
 *
 * @param <PR> type of {@link PrivateKey}.
 * @param <PU> type of {@link PublicKey}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class SecurityAsymmetricCryptorConfig<PR extends PrivateKey, PU extends PublicKey> extends SecurityCryptorConfig {

  /**
   * The constructor.
   *
   * @param transformation the {@link #getTransformation() transfomation} for the {@link javax.crypto.Cipher}.
   * @param nonceSize the {@link #getNonceSize() nonce size}.
   * @param provider the {@link SecurityProvider}.
   */
  public SecurityAsymmetricCryptorConfig(SecurityCipherTransformation transformation, int nonceSize, SecurityProvider provider) {

    super(transformation, provider, nonceSize);
  }

  /**
   * @return {@code true} if the underlying asymmetric encryption algorithm is bidirectional and also allows to encrypt
   *         with private key and decrypt with public key (like e.g. RSA), {@code false} otherwise (default).
   */
  public boolean isBidirectional() {

    return false;
  }

}
