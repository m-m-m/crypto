package net.sf.mmm.security.api.key.asymmetric.rsa;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.function.Supplier;

import net.sf.mmm.security.api.key.asymmetric.AbstractSecurityAsymmetricKeyPairFactory;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyPairFactory;

/**
 * Implementation of {@link SecurityAsymmetricKeyPairFactory} for {@link net.sf.mmm.security.api.crypt.asymmetric.Rsa}.
 *
 * @since 1.0.0
 */
public class SecurityAsymmetricKeyPairFactoryRsa extends
    AbstractSecurityAsymmetricKeyPairFactory<RSAPrivateKey, RSAPublicKey, SecurityPrivateKeyRsa, SecurityPublicKeyRsa, SecurityAsymmetricKeyPairRsa> {

  private static final SecurityAsymmetricKeyPairFactoryRsa INSTANCE = new SecurityAsymmetricKeyPairFactoryRsa();

  @Override
  public SecurityPrivateKeyRsa createPrivateKey(RSAPrivateKey privateKey) {

    return new SecurityPrivateKeyRsa(privateKey);
  }

  @Override
  public SecurityPrivateKeyRsa createPrivateKey(byte[] data, Supplier<RSAPrivateKey> keySupplier) {

    return new SecurityPrivateKeyRsa(data, keySupplier);
  }

  @Override
  public SecurityPublicKeyRsa createPublicKey(RSAPublicKey publicKey) {

    return new SecurityPublicKeyRsa(publicKey);
  }

  @Override
  public SecurityPublicKeyRsa createPublicKey(byte[] data, Supplier<RSAPublicKey> keySupplier) {

    return new SecurityPublicKeyRsa(data, keySupplier);
  }

  @Override
  public SecurityAsymmetricKeyPairRsa createKeyPair(SecurityPrivateKeyRsa privateKey, SecurityPublicKeyRsa publicKey) {

    return new SecurityAsymmetricKeyPairRsa(privateKey, publicKey);
  }

  @Override
  public Class<SecurityAsymmetricKeyPairRsa> getSecurityAsymmetricKeyPairClass() {

    return SecurityAsymmetricKeyPairRsa.class;
  }

  @Override
  public Class<SecurityPrivateKeyRsa> getSecurityPrivateKeyClass() {

    return SecurityPrivateKeyRsa.class;
  }

  @Override
  public Class<SecurityPublicKeyRsa> getSecurityPublicKeyClass() {

    return SecurityPublicKeyRsa.class;
  }

  /**
   * @return the singleton instance.
   */
  public static SecurityAsymmetricKeyPairFactoryRsa get() {

    return INSTANCE;
  }

}
