package net.sf.mmm.security.api.asymmetric.key.generic;

import java.security.PrivateKey;
import java.security.PublicKey;

import net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyPairFactorySimple;

/**
 * Implementation of {@link SecurityAsymmetricKeyPairFactorySimple} for {@link SecurityAsymmetricKeyPairGeneric}.
 *
 * @since 1.0.0
 */
public class SecurityAsymmetricKeyPairFactoryGeneric
    implements SecurityAsymmetricKeyPairFactorySimple<PrivateKey, PublicKey, SecurityAsymmetricKeyPairGeneric> {

  static final SecurityAsymmetricKeyPairFactoryGeneric INSTANCE = new SecurityAsymmetricKeyPairFactoryGeneric();

  @Override
  public SecurityAsymmetricKeyPairGeneric createKeyPair(PrivateKey privateKey, PublicKey publicKey) {

    return new SecurityAsymmetricKeyPairGeneric(privateKey, publicKey);
  }

  /**
   * @return the singleton instance.
   */
  public static final SecurityAsymmetricKeyPairFactoryGeneric get() {

    return INSTANCE;
  }

}
