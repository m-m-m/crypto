package net.sf.mmm.security.api.asymmetric.key.ec.bc;

import java.security.KeyPairGenerator;
import java.util.Objects;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmEc;
import net.sf.mmm.security.api.algorithm.SecurityAlgorithmRsa;
import net.sf.mmm.security.api.asymmetric.key.AbstractSecurityAsymmetricKeyCreator;
import net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyCreator;
import net.sf.mmm.security.api.asymmetric.key.ec.SecurityAsymmetricKeyPairEc;
import net.sf.mmm.security.api.provider.BouncyCastle;
import net.sf.mmm.security.api.provider.SecurityProvider;
import net.sf.mmm.security.api.random.SecurityRandomFactory;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;

/**
 * Implementation of {@link SecurityAsymmetricKeyCreator} for {@link SecurityAlgorithmRsa RSA}.
 *
 * @since 1.0.0
 */
public class SecurityAsymmetricKeyCreatorEcBc extends
    AbstractSecurityAsymmetricKeyCreator<BCECPrivateKey, BCECPublicKey, SecurityAsymmetricKeyPairEcBc> implements SecurityAlgorithmEc {

  private final ECParameterSpec ecParameters;

  /**
   * The constructor.
   *
   * @param ecParameters the {@link ECParameterSpec}.
   */
  public SecurityAsymmetricKeyCreatorEcBc(ECParameterSpec ecParameters) {

    this(ecParameters, null);
  }

  /**
   * The constructor.
   *
   * @param ecParameters the {@link ECParameterSpec}.
   * @param randomFactory the {@link #getRandomFactory() random factory}.
   */
  public SecurityAsymmetricKeyCreatorEcBc(ECParameterSpec ecParameters, SecurityRandomFactory randomFactory) {

    super(SecurityAsymmetricKeyPairEcBc.getKeyFactory(), ecParameters.getCurve().getOrder().bitLength(),
        SecurityProvider.of(BouncyCastle.getProvider()), randomFactory);
    this.ecParameters = ecParameters;
    register(new SecurityAsymmetricKeyPairFactoryEcBcCompact(ecParameters));
    register(new SecurityAsymmetricKeyPairFactoryEcBcUncompressed(ecParameters), SecurityAsymmetricKeyPairEc.FORMAT_UNCOMORESSED);
  }

  @Override
  public SecurityAsymmetricKeyPairEcBc createKeyPair(BCECPrivateKey privateKey, BCECPublicKey publicKey) {

    return new SecurityAsymmetricKeyPairEcBc(privateKey, publicKey);
  }

  @Override
  public int getKeyLength(BCECPrivateKey privateKey) {

    Objects.requireNonNull(privateKey, "privateKey");
    return privateKey.getParameters().getCurve().getOrder().bitLength();
  }

  @Override
  public void verifyKey(BCECPrivateKey privateKey) {

    super.verifyKey(privateKey);
    if (!Objects.equals(this.ecParameters, privateKey.getParameters())) {
      throw new IllegalArgumentException("PRivate key has different elliptic curve!");
    }
  }

  @Override
  public int getKeyLength(BCECPublicKey publicKey) {

    Objects.requireNonNull(publicKey, "publicKey");
    return publicKey.getParameters().getCurve().getOrder().bitLength();
  }

  @Override
  public void verifyKey(BCECPublicKey publicKey) {

    super.verifyKey(publicKey);
    if (!Objects.equals(this.ecParameters, publicKey.getParameters())) {
      throw new IllegalArgumentException("Public key has different elliptic curve!");
    }
  }

  @Override
  protected void init(KeyPairGenerator keyPairGenerator) throws Exception {

    keyPairGenerator.initialize(this.ecParameters, createSecureRandom());
  }

}
