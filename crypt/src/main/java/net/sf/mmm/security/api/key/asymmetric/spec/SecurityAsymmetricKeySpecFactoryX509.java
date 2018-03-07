package net.sf.mmm.security.api.key.asymmetric.spec;

import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;

import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeySpecFactory;

/**
 * Implementation of {@link SecurityAsymmetricKeySpecFactory} for X.509 ({@link X509EncodedKeySpec}).
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityAsymmetricKeySpecFactoryX509 implements SecurityAsymmetricKeySpecFactory {

  /** The singleton instance. */
  public static final SecurityAsymmetricKeySpecFactoryX509 INSTANCE =
      new SecurityAsymmetricKeySpecFactoryX509();

  @Override
  public KeySpec createKeySpec(byte[] key) {

    return new X509EncodedKeySpec(key);
  }

}
