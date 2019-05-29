package net.sf.mmm.crypto.crypt;

import java.security.Key;

import net.sf.mmm.crypto.random.RandomFactory;

/**
 * Implementation of {@link Decryptor} based on {@link javax.crypto.Cipher}.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class DecryptorImplCipher extends CryptorImplCipher implements AbstractDecryptor {

  /**
   * The constructor.
   *
   * @param randomFactory the {@link RandomFactory} to use.
   * @param config the {@link CryptorConfig}.
   * @param key the {@link Key} to use.
   */
  public DecryptorImplCipher(RandomFactory randomFactory, CryptorConfig config, Key key) {

    super(randomFactory, config, key);
  }

  @Override
  protected boolean isEncryptor() {

    return false;
  }

}
