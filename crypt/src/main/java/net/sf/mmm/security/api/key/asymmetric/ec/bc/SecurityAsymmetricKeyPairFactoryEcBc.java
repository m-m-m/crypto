package net.sf.mmm.security.api.key.asymmetric.ec.bc;

import java.util.function.Supplier;

import net.sf.mmm.security.api.key.asymmetric.AbstractSecurityAsymmetricKeyPairFactory;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyPairFactory;

import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;

/**
 * Implementation of {@link SecurityAsymmetricKeyPairFactory} for
 * {@link net.sf.mmm.security.api.algorithm.SecurityAlgorithmEc EC} and {@code bouncy castle}.
 *
 * @since 1.0.0
 */
public class SecurityAsymmetricKeyPairFactoryEcBc extends
    AbstractSecurityAsymmetricKeyPairFactory<ECPrivateKey, ECPublicKey, SecurityPrivateKeyEcBc, SecurityPublicKeyEcBc, SecurityAsymmetricKeyPairEcBc> {

  private static final SecurityAsymmetricKeyPairFactoryEcBc INSTANCE = new SecurityAsymmetricKeyPairFactoryEcBc();

  @Override
  public SecurityPrivateKeyEcBc createPrivateKey(ECPrivateKey privateKey) {

    return new SecurityPrivateKeyEcBc(privateKey);
  }

  @Override
  public SecurityPrivateKeyEcBc createPrivateKey(byte[] data, Supplier<ECPrivateKey> keySupplier) {

    return new SecurityPrivateKeyEcBc(data, keySupplier);
  }

  @Override
  public SecurityPublicKeyEcBc createPublicKey(ECPublicKey publicKey) {

    return new SecurityPublicKeyEcBc(publicKey);
  }

  @Override
  public SecurityPublicKeyEcBc createPublicKey(byte[] data, Supplier<ECPublicKey> keySupplier) {

    return new SecurityPublicKeyEcBc(data, keySupplier);
  }

  @Override
  public SecurityAsymmetricKeyPairEcBc createKeyPair(SecurityPrivateKeyEcBc privateKey, SecurityPublicKeyEcBc publicKey) {

    return new SecurityAsymmetricKeyPairEcBc(privateKey, publicKey);
  }

  @Override
  public Class<SecurityAsymmetricKeyPairEcBc> getSecurityAsymmetricKeyPairClass() {

    return SecurityAsymmetricKeyPairEcBc.class;
  }

  @Override
  public Class<SecurityPrivateKeyEcBc> getSecurityPrivateKeyClass() {

    return SecurityPrivateKeyEcBc.class;
  }

  @Override
  public Class<SecurityPublicKeyEcBc> getSecurityPublicKeyClass() {

    return SecurityPublicKeyEcBc.class;
  }

  /**
   * @return the singleton instance.
   */
  public static final SecurityAsymmetricKeyPairFactoryEcBc get() {

    return INSTANCE;
  }

}
