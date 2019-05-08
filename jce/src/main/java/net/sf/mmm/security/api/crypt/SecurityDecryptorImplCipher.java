package net.sf.mmm.security.api.crypt;

import java.security.Key;

import net.sf.mmm.security.api.random.SecurityRandomFactory;

/**
 * Implementation of {@link SecurityDecryptor} based on {@link javax.crypto.Cipher}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityDecryptorImplCipher extends SecurityCryptorImplCipher implements AbstractSecurityDecryptor {

  /**
   * The constructor.
   *
   * @param randomFactory the {@link SecurityRandomFactory} to use.
   * @param config the {@link SecurityCryptorConfig}.
   * @param key the {@link Key} to use.
   */
  public SecurityDecryptorImplCipher(SecurityRandomFactory randomFactory, SecurityCryptorConfig config, Key key) {

    super(randomFactory, config, key);
  }

  @Override
  protected boolean isEncryptor() {

    return false;
  }

}
