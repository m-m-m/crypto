package net.sf.mmm.crypto.symmetric.access.pbe;

import net.sf.mmm.crypto.provider.BouncyCastle;
import net.sf.mmm.crypto.symmetric.crypt.SymmetricCryptorConfig;
import net.sf.mmm.crypto.symmetric.crypt.aes.SymmetricCryptorConfigAes;
import net.sf.mmm.crypto.symmetric.key.pbe.SymmetricKeyConfigPbe;

/**
 * {@link PbeAccess} for <a href="https://en.wikipedia.org/wiki/PBKDF2">PBKDF2</a> (Password-Based Key Derivation
 * Function 2) from <em>PKCS #5 v2.0</em>.
 *
 * @since 1.0.0
 */
public class Pbkdf2 extends PbeAccess {

  static final SymmetricCryptorConfigAes CRYPTOR_CONFIG_AES = new SymmetricCryptorConfigAes(BouncyCastle.getSecurityProvider());

  /**
   * The constructor.
   *
   * @param keyConfig the {@link SymmetricKeyConfigPbe}.
   */
  Pbkdf2(SymmetricKeyConfigPbe keyConfig) {

    super(keyConfig, CRYPTOR_CONFIG_AES);
  }

  /**
   * The constructor.
   *
   * @param keyConfig the {@link SymmetricKeyConfigPbe}.
   * @param cryptorConfig the {@link SymmetricCryptorConfig}.
   */
  Pbkdf2(SymmetricKeyConfigPbe keyConfig, SymmetricCryptorConfig cryptorConfig) {

    super(keyConfig, cryptorConfig);
  }

  /**
   * The constructor.
   *
   * @param keyAlgorithm the {@link SymmetricKeyConfigPbe#getAlgorithm() key algorithm}.
   * @param keyLength the {@link #getKeyLength() key-length}.
   */
  Pbkdf2(String keyAlgorithm, int keyLength) {

    this(keyAlgorithm, keyLength, CRYPTOR_CONFIG_AES);
  }

  /**
   * The constructor.
   *
   * @param keyAlgorithm the {@link SymmetricKeyConfigPbe#getAlgorithm() key algorithm}.
   * @param keyLength the {@link #getKeyLength() key-length}.
   * @param cryptorConfig the {@link SymmetricCryptorConfig}.
   */
  Pbkdf2(String keyAlgorithm, int keyLength, SymmetricCryptorConfig cryptorConfig) {

    super(new SymmetricKeyConfigPbe(keyAlgorithm, BouncyCastle.getSecurityProvider(), keyLength), cryptorConfig);
  }

}
