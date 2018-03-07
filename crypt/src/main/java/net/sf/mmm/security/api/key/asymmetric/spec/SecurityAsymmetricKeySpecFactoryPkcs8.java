package net.sf.mmm.security.api.key.asymmetric.spec;

import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeySpecFactory;

/**
 * Implementation of {@link SecurityAsymmetricKeySpecFactory} for PKCS8 ({@link PKCS8EncodedKeySpec}).
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityAsymmetricKeySpecFactoryPkcs8 implements SecurityAsymmetricKeySpecFactory {

  /** The singleton instance. */
  public static final SecurityAsymmetricKeySpecFactoryPkcs8 INSTANCE =
      new SecurityAsymmetricKeySpecFactoryPkcs8();

  @Override
  public KeySpec createKeySpec(byte[] key) {

    return new PKCS8EncodedKeySpec(key);
  }

}
