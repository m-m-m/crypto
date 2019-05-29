package net.sf.mmm.crypto.symmetric.access.pbe;

import javax.crypto.interfaces.PBEKey;

import net.sf.mmm.crypto.symmetric.access.SymmetricAccess;
import net.sf.mmm.crypto.symmetric.crypt.SymmetricCryptorConfig;
import net.sf.mmm.crypto.symmetric.key.pbe.SecuritySymmetricKeyConfigPbe;

/**
 * {@link SymmetricAccess} for PBE (Password Based Encryption).
 *
 * @since 1.0.0
 */
public class PbeAccess extends SymmetricAccess<PBEKey> {

  /**
   * The constructor.
   *
   * @param keyConfig the {@link SecuritySymmetricKeyConfigPbe}.
   * @param cryptorConfig the {@link SymmetricCryptorConfig}.
   */
  public PbeAccess(SecuritySymmetricKeyConfigPbe keyConfig, SymmetricCryptorConfig cryptorConfig) {

    super(keyConfig, cryptorConfig);
  }

}
