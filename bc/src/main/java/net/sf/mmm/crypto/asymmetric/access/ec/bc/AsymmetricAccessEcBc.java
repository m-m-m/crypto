/* Copyright (c) The m-m-m Team, Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0 */
package net.sf.mmm.crypto.asymmetric.access.ec.bc;

import net.sf.mmm.crypto.asymmetric.access.AsymmetricAccess;
import net.sf.mmm.crypto.asymmetric.crypt.ec.AsymmetricCryptorConfigEcIes;
import net.sf.mmm.crypto.asymmetric.key.ec.bc.AsymmetricKeyCreatorEcBc;
import net.sf.mmm.crypto.asymmetric.key.ec.bc.AsymmetricKeyPairEcBc;
import net.sf.mmm.crypto.asymmetric.sign.SignatureConfig;
import net.sf.mmm.crypto.asymmetric.sign.ec.SignatureConfigEcDsa;
import net.sf.mmm.crypto.asymmetric.sign.ec.bc.SignatureEcBc;
import net.sf.mmm.crypto.asymmetric.sign.ec.bc.SignatureFactoryEcBc;
import net.sf.mmm.crypto.asymmetric.sign.ec.bc.SignatureProcessorFactoryImplEcBc;
import net.sf.mmm.crypto.hash.HashConfig;
import net.sf.mmm.crypto.provider.BouncyCastle;
import net.sf.mmm.crypto.provider.SecurityProvider;
import net.sf.mmm.crypto.random.RandomFactory;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;

/**
 * {@link AsymmetricAccess} for <a href="https://en.wikipedia.org/wiki/Elliptic_curve_cryptography">ECC</a>
 * based on {@link BouncyCastle}.
 *
 * @param <S> type of {@link SignatureEcBc}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class AsymmetricAccessEcBc<S extends SignatureEcBc>
    extends AsymmetricAccess<S, BCECPrivateKey, BCECPublicKey, AsymmetricKeyPairEcBc, AsymmetricKeyCreatorEcBc> {

  /** The {@link ECParameterSpec} of the elliptic curve. */
  protected final ECParameterSpec ecParameters;

  /**
   * The constructor.
   *
   * @param ecParameters the {@link ECParameterSpec}.
   * @param signatureConfig the {@link SignatureConfig}.
   * @param cryptorConfig the {@link AsymmetricCryptorConfigEcIes}.
   * @param randomFactory the optional {@link RandomFactory}.
   */
  public AsymmetricAccessEcBc(ECParameterSpec ecParameters, SignatureConfig<S> signatureConfig,
      AsymmetricCryptorConfigEcIes<BCECPrivateKey, BCECPublicKey> cryptorConfig, RandomFactory randomFactory) {

    super(signatureConfig, new SignatureProcessorFactoryImplEcBc<>((SignatureConfigEcDsa<S>) signatureConfig),
        cryptorConfig, randomFactory);
    this.ecParameters = ecParameters;
  }

  /**
   * The constructor.
   *
   * @param ecParameters the {@link ECParameterSpec}.
   * @param signatureFactory the {@link SignatureFactoryEcBc}.
   * @param hashConfig the {@link HashConfig} for the hash used for signatures.
   * @param randomFactory the {@link RandomFactory}.
   */
  public AsymmetricAccessEcBc(ECParameterSpec ecParameters, SignatureFactoryEcBc<S> signatureFactory, HashConfig hashConfig,
      RandomFactory randomFactory) {

    this(ecParameters, signatureFactory, hashConfig, randomFactory, BouncyCastle.getSecurityProvider());
  }

  private AsymmetricAccessEcBc(ECParameterSpec ecParameters, SignatureFactoryEcBc<S> signatureFactory, HashConfig hashConfig,
      RandomFactory randomFactory, SecurityProvider provider) {

    this(ecParameters, new SignatureConfigEcDsa<>(signatureFactory, hashConfig, provider),
        new AsymmetricCryptorConfigEcIes<>(provider), randomFactory);
  }

  @Override
  public AsymmetricKeyCreatorEcBc newKeyCreator() {

    return new AsymmetricKeyCreatorEcBc(this.ecParameters, this.randomFactory);
  }

}
