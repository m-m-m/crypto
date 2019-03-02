package net.sf.mmm.security.api.key.asymmetric.generic;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.function.Supplier;

import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyPairFactory;
import net.sf.mmm.security.api.key.asymmetric.SecurityPrivateKey;
import net.sf.mmm.security.api.key.asymmetric.SecurityPublicKey;

/**
 * Implementation of {@link SecurityAsymmetricKeyPairFactory} for {@link net.sf.mmm.security.api.crypt.asymmetric.Rsa}.
 *
 * @since 1.0.0
 */
public class SecurityAsymmetricKeyPairFactoryGeneric implements
    SecurityAsymmetricKeyPairFactory<PrivateKey, PublicKey, SecurityPrivateKey, SecurityPublicKey, SecurityAsymmetricKeyPairGeneric> {

  private static final SecurityAsymmetricKeyPairFactoryGeneric INSTANCE = new SecurityAsymmetricKeyPairFactoryGeneric();

  @Override
  public SecurityPrivateKey createPrivateKey(PrivateKey privateKey) {

    return new SecurityPrivateKeyGeneric(privateKey);
  }

  @Override
  public SecurityPrivateKey createPrivateKey(byte[] data, Supplier<PrivateKey> keySupplier) {

    return new SecurityPrivateKeyGeneric(data, keySupplier);
  }

  @Override
  public SecurityPublicKey createPublicKey(PublicKey publicKey) {

    return new SecurityPublicKeyGeneric(publicKey);
  }

  @Override
  public SecurityPublicKey createPublicKey(byte[] data, Supplier<PublicKey> keySupplier) {

    return new SecurityPublicKeyGeneric(data, keySupplier);
  }

  @Override
  public SecurityAsymmetricKeyPairGeneric createKeyPair(SecurityPrivateKey privateKey, SecurityPublicKey publicKey) {

    return new SecurityAsymmetricKeyPairGeneric(privateKey, publicKey);
  }

  @Override
  public Class<SecurityAsymmetricKeyPairGeneric> getSecurityAsymmetricKeyPairClass() {

    return SecurityAsymmetricKeyPairGeneric.class;
  }

  @Override
  public Class<SecurityPrivateKey> getSecurityPrivateKeyClass() {

    return SecurityPrivateKey.class;
  }

  @Override
  public Class<SecurityPublicKey> getSecurityPublicKeyClass() {

    return SecurityPublicKey.class;
  }

  /**
   * @return the singleton instance.
   */
  public static SecurityAsymmetricKeyPairFactoryGeneric get() {

    return INSTANCE;
  }

}
