package io.github.mmm.crypto.asymmetric.key.ec.bc;

import java.security.KeyPairGenerator;
import java.util.Objects;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;

import io.github.mmm.crypto.asymmetric.key.AbstractAsymmetricKeyCreator;
import io.github.mmm.crypto.asymmetric.key.AsymmetricKeyCreator;
import io.github.mmm.crypto.asymmetric.key.ec.AsymmetricKeyPairEc;
import io.github.mmm.crypto.provider.SecurityProvider;
import io.github.mmm.crypto.provider.bc.BouncyCastle;
import io.github.mmm.crypto.random.RandomFactory;

/**
 * Implementation of {@link AsymmetricKeyCreator} for {@link AsymmetricKeyPairEcBc}.
 *
 * @since 1.0.0
 */
public class AsymmetricKeyCreatorEcBc
    extends AbstractAsymmetricKeyCreator<BCECPrivateKey, BCECPublicKey, AsymmetricKeyPairEcBc> {

  private final ECParameterSpec ecParameters;

  /**
   * The constructor.
   *
   * @param ecParameters the {@link ECParameterSpec}.
   */
  public AsymmetricKeyCreatorEcBc(ECParameterSpec ecParameters) {

    this(ecParameters, null);
  }

  /**
   * The constructor.
   *
   * @param ecParameters the {@link ECParameterSpec}.
   * @param randomFactory the {@link #getRandomFactory() random factory}.
   */
  public AsymmetricKeyCreatorEcBc(ECParameterSpec ecParameters, RandomFactory randomFactory) {

    super(AsymmetricKeyPairEcBc.getKeyFactory(), ecParameters.getCurve().getOrder().bitLength(),
        SecurityProvider.of(BouncyCastle.getProvider()), randomFactory);
    this.ecParameters = ecParameters;
    register(new AsymmetricKeyPairFactoryEcBcCompact(ecParameters));
    register(new AsymmetricKeyPairFactoryEcBcUncompressed(ecParameters), AsymmetricKeyPairEc.FORMAT_UNCOMORESSED);
  }

  @Override
  public AsymmetricKeyPairEcBc createKeyPair(BCECPrivateKey privateKey, BCECPublicKey publicKey) {

    return new AsymmetricKeyPairEcBc(privateKey, publicKey);
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
