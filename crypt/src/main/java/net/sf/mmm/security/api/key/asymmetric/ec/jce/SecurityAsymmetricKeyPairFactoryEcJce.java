package net.sf.mmm.security.api.key.asymmetric.ec.jce;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.function.Supplier;

import net.sf.mmm.security.api.key.asymmetric.AbstractSecurityAsymmetricKeyPairFactory;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyPairFactory;

/**
 * Implementation of {@link SecurityAsymmetricKeyPairFactory} for
 * {@link net.sf.mmm.security.api.algorithm.SecurityAlgorithmEc EC} and {@code bouncy castle}.
 *
 * @since 1.0.0
 */
public class SecurityAsymmetricKeyPairFactoryEcJce extends
    AbstractSecurityAsymmetricKeyPairFactory<ECPrivateKey, ECPublicKey, SecurityPrivateKeyEcJce, SecurityPublicKeyEcJce, SecurityAsymmetricKeyPairEcJce> {

  private static final SecurityAsymmetricKeyPairFactoryEcJce INSTANCE = new SecurityAsymmetricKeyPairFactoryEcJce();

  @Override
  public SecurityPrivateKeyEcJce createPrivateKey(ECPrivateKey privateKey) {

    return new SecurityPrivateKeyEcJce(privateKey);
  }

  @Override
  public SecurityPrivateKeyEcJce createPrivateKey(byte[] data, Supplier<ECPrivateKey> keySupplier) {

    return new SecurityPrivateKeyEcJce(data, keySupplier);
  }

  @Override
  public SecurityPublicKeyEcJce createPublicKey(ECPublicKey publicKey) {

    return new SecurityPublicKeyEcJce(publicKey);
  }

  @Override
  public SecurityPublicKeyEcJce createPublicKey(byte[] data, Supplier<ECPublicKey> keySupplier) {

    return new SecurityPublicKeyEcJce(data, keySupplier);
  }

  @Override
  public SecurityAsymmetricKeyPairEcJce createKeyPair(SecurityPrivateKeyEcJce privateKey, SecurityPublicKeyEcJce publicKey) {

    return new SecurityAsymmetricKeyPairEcJce(privateKey, publicKey);
  }

  @Override
  public Class<SecurityAsymmetricKeyPairEcJce> getSecurityAsymmetricKeyPairClass() {

    return SecurityAsymmetricKeyPairEcJce.class;
  }

  @Override
  public Class<SecurityPrivateKeyEcJce> getSecurityPrivateKeyClass() {

    return SecurityPrivateKeyEcJce.class;
  }

  @Override
  public Class<SecurityPublicKeyEcJce> getSecurityPublicKeyClass() {

    return SecurityPublicKeyEcJce.class;
  }

  /**
   * @return the singleton instance.
   */
  public static final SecurityAsymmetricKeyPairFactoryEcJce get() {

    return INSTANCE;
  }

}
