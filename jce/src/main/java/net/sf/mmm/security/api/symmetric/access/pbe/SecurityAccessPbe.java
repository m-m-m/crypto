package net.sf.mmm.security.api.symmetric.access.pbe;

import javax.crypto.interfaces.PBEKey;

import net.sf.mmm.security.api.symmetric.access.SecurityAccessSymmetric;
import net.sf.mmm.security.api.symmetric.crypt.SecuritySymmetricCryptorConfig;
import net.sf.mmm.security.api.symmetric.key.pbe.SecuritySymmetricKeyConfigPbe;

/**
 * {@link SecurityAccessSymmetric} for PBE (Password Based Encryption).
 *
 * @since 1.0.0
 */
public class SecurityAccessPbe extends SecurityAccessSymmetric<PBEKey> {

  /**
   * The constructor.
   *
   * @param keyConfig the {@link SecuritySymmetricKeyConfigPbe}.
   * @param cryptorConfig the {@link SecuritySymmetricCryptorConfig}.
   */
  public SecurityAccessPbe(SecuritySymmetricKeyConfigPbe keyConfig, SecuritySymmetricCryptorConfig cryptorConfig) {

    super(keyConfig, cryptorConfig);
  }

}
