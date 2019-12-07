package io.github.mmm.crypto.asymmetric.crypt;

import java.security.PrivateKey;
import java.security.PublicKey;

import io.github.mmm.crypto.crypt.CipherTransformation;
import io.github.mmm.crypto.crypt.CryptorConfig;
import io.github.mmm.crypto.provider.SecurityProvider;

/**
 * {@link CryptorConfig} for {@link io.github.mmm.crypto.asymmetric.key.AsymmetricKeyPair asymmetric
 * cryptography}.
 *
 * @param <PR> type of {@link PrivateKey}.
 * @param <PU> type of {@link PublicKey}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class AsymmetricCryptorConfig<PR extends PrivateKey, PU extends PublicKey> extends CryptorConfig {

  /**
   * The constructor.
   *
   * @param transformation the {@link #getTransformation() transfomation} for the {@link javax.crypto.Cipher}.
   * @param nonceSize the {@link #getNonceSize() nonce size}.
   * @param provider the {@link SecurityProvider}.
   */
  public AsymmetricCryptorConfig(CipherTransformation transformation, int nonceSize, SecurityProvider provider) {

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
