package net.sf.mmm.security.api.symmetric.access.pbe;

import net.sf.mmm.security.api.provider.BouncyCastle;
import net.sf.mmm.security.api.symmetric.crypt.SecuritySymmetricCryptorConfig;
import net.sf.mmm.security.api.symmetric.crypt.SecuritySymmetricCryptorConfigAes;
import net.sf.mmm.security.api.symmetric.key.pbe.SecuritySymmetricKeyConfigPbe;

/**
 * {@link SecurityAccessPbe} for <a href="https://en.wikipedia.org/wiki/PBKDF2">PBKDF2</a> (Password-Based Key
 * Derivation Function 2) from <em>PKCS #5 v2.0</em>.
 *
 * @since 1.0.0
 */
public class Pbkdf2 extends SecurityAccessPbe {

  static final SecuritySymmetricCryptorConfigAes CRYPTOR_CONFIG_AES = new SecuritySymmetricCryptorConfigAes(
      BouncyCastle.getSecurityProvider());

  /**
   * The constructor.
   *
   * @param keyConfig the {@link SecuritySymmetricKeyConfigPbkdf2}.
   */
  Pbkdf2(SecuritySymmetricKeyConfigPbe keyConfig) {

    super(keyConfig, CRYPTOR_CONFIG_AES);
  }

  /**
   * The constructor.
   *
   * @param keyConfig the {@link SecuritySymmetricKeyConfigPbkdf2}.
   * @param cryptorConfig the {@link SecuritySymmetricCryptorConfig}.
   */
  Pbkdf2(SecuritySymmetricKeyConfigPbe keyConfig, SecuritySymmetricCryptorConfig cryptorConfig) {

    super(keyConfig, cryptorConfig);
  }

  /**
   * The constructor.
   *
   * @param keyConfig the {@link SecuritySymmetricKeyConfigPbkdf2}.
   * @param cryptorConfig the {@link SecuritySymmetricCryptorConfig}.
   */
  Pbkdf2(String keyAlgorithm, int keyLength) {

    this(keyAlgorithm, keyLength, CRYPTOR_CONFIG_AES);
  }

  /**
   * The constructor.
   *
   * @param keyConfig the {@link SecuritySymmetricKeyConfigPbkdf2}.
   * @param cryptorConfig the {@link SecuritySymmetricCryptorConfig}.
   */
  Pbkdf2(String keyAlgorithm, int keyLength, SecuritySymmetricCryptorConfig cryptorConfig) {

    super(new SecuritySymmetricKeyConfigPbe(keyAlgorithm, BouncyCastle.getSecurityProvider(), keyLength), cryptorConfig);
  }

}
