package net.sf.mmm.security.api.key.asymmetric.generic;

import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

import net.sf.mmm.security.api.key.asymmetric.SecurityPrivateKeySpecFactory;

/**
 * Implementation of {@link SecurityPrivateKeySpecFactory} for PKCS8 ({@link PKCS8EncodedKeySpec}).
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityAsymmetricKeySpecFactoryPkcs8 implements SecurityPrivateKeySpecFactory {

  /** The singleton instance. */
  public static final SecurityAsymmetricKeySpecFactoryPkcs8 INSTANCE = new SecurityAsymmetricKeySpecFactoryPkcs8();

  @Override
  public KeySpec createKeySpec(byte[] key) {

    return new PKCS8EncodedKeySpec(key);
  }

}
