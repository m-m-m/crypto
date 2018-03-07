package net.sf.mmm.security.impl.crypt;

import java.security.Key;
import java.security.Provider;

import javax.crypto.Cipher;

import net.sf.mmm.security.api.crypt.SecurityCryptorConfig;
import net.sf.mmm.security.api.crypt.SecurityEncryptor;
import net.sf.mmm.security.api.random.SecurityRandomFactory;

/**
 * Implementation of {@link SecurityEncryptor} based on {@link Cipher}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityEncryptorImplCiper extends SecurityCryptorImplCipher implements AbstractSecurityEncryptor {

  /**
   * The constructor.
   *
   * @param provider the optional security {@link Provider}.
   * @param randomFactory the {@link SecurityRandomFactory} to use.
   * @param config the {@link SecurityCryptorConfig}.
   * @param key the {@link Key} to use.
   */
  public SecurityEncryptorImplCiper(Provider provider, SecurityRandomFactory randomFactory,
      SecurityCryptorConfig<?> config, Key key) {
    super(provider, randomFactory, config, key);
  }

  @Override
  protected boolean isEncryptor() {

    return true;
  }

}
