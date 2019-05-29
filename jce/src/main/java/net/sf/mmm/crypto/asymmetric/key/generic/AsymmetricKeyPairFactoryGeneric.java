package net.sf.mmm.crypto.asymmetric.key.generic;

import java.security.PrivateKey;
import java.security.PublicKey;

import net.sf.mmm.crypto.asymmetric.key.AsymmetricKeyPairFactorySimple;

/**
 * Implementation of {@link AsymmetricKeyPairFactorySimple} for {@link AsymmetricKeyPairGeneric}.
 *
 * @since 1.0.0
 */
public class AsymmetricKeyPairFactoryGeneric
    implements AsymmetricKeyPairFactorySimple<PrivateKey, PublicKey, AsymmetricKeyPairGeneric> {

  static final AsymmetricKeyPairFactoryGeneric INSTANCE = new AsymmetricKeyPairFactoryGeneric();

  @Override
  public AsymmetricKeyPairGeneric createKeyPair(PrivateKey privateKey, PublicKey publicKey) {

    return new AsymmetricKeyPairGeneric(privateKey, publicKey);
  }

  /**
   * @return the singleton instance.
   */
  public static final AsymmetricKeyPairFactoryGeneric get() {

    return INSTANCE;
  }

}
