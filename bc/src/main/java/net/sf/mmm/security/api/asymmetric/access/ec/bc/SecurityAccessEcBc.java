/* Copyright (c) The m-m-m Team, Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0 */
package net.sf.mmm.security.api.asymmetric.access.ec.bc;

import net.sf.mmm.security.api.algorithm.SecurityAlgorithmEc;
import net.sf.mmm.security.api.algorithm.SecurityAlgorithmEcDsa;
import net.sf.mmm.security.api.algorithm.SecurityAlgorithmEcIes;
import net.sf.mmm.security.api.asymmetric.access.SecurityAccessAsymmetric;
import net.sf.mmm.security.api.asymmetric.crypt.ec.SecurityAsymmetricCryptorConfigEcies;
import net.sf.mmm.security.api.asymmetric.key.ec.bc.SecurityAsymmetricKeyCreatorEcBc;
import net.sf.mmm.security.api.asymmetric.key.ec.bc.SecurityAsymmetricKeyPairEcBc;
import net.sf.mmm.security.api.asymmetric.sign.SecuritySignatureConfig;
import net.sf.mmm.security.api.asymmetric.sign.ec.bc.SecuritySignatureEcBc;
import net.sf.mmm.security.api.asymmetric.sign.ec.bc.SecuritySignatureFactoryEcBc;
import net.sf.mmm.security.api.asymmetric.sign.ec.bc.SecuritySignatureProcessorFactoryImplEcBc;
import net.sf.mmm.security.api.hash.SecurityHashConfig;
import net.sf.mmm.security.api.provider.BouncyCastle;
import net.sf.mmm.security.api.provider.SecurityProvider;
import net.sf.mmm.security.api.random.SecurityRandomFactory;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;

/**
 * {@link SecurityAccessAsymmetric} for {@link SecurityAlgorithmEc ECC} based on BouncyCastle.
 *
 * @param <S> type of {@link SecuritySignatureEcBc}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class SecurityAccessEcBc<S extends SecuritySignatureEcBc>
    extends SecurityAccessAsymmetric<S, BCECPrivateKey, BCECPublicKey, SecurityAsymmetricKeyPairEcBc, SecurityAsymmetricKeyCreatorEcBc>
    implements SecurityAlgorithmEcIes {

  /** The {@link ECParameterSpec} of the elliptic curve. */
  protected final ECParameterSpec ecParameters;

  /**
   * The constructor.
   *
   * @param ecParameters the {@link ECParameterSpec}.
   * @param signatureConfig the {@link SecuritySignatureConfig}.
   * @param cryptorConfig the {@link SecurityAsymmetricCryptorConfigEcies}.
   * @param randomFactory the optional {@link SecurityRandomFactory}.
   */
  public SecurityAccessEcBc(ECParameterSpec ecParameters, SecuritySignatureConfig<S> signatureConfig,
      SecurityAsymmetricCryptorConfigEcies<BCECPrivateKey, BCECPublicKey> cryptorConfig, SecurityRandomFactory randomFactory) {

    super(new SecuritySignatureProcessorFactoryImplEcBc<>(signatureConfig), cryptorConfig, randomFactory);
    this.ecParameters = ecParameters;
  }

  /**
   * The constructor.
   *
   * @param ecParameters the {@link ECParameterSpec}.
   * @param signatureFactory the {@link SecuritySignatureFactoryEcBc}.
   * @param hashConfig the {@link SecurityHashConfig} for the hash used for signatures.
   * @param randomFactory the {@link SecurityRandomFactory}.
   */
  public SecurityAccessEcBc(ECParameterSpec ecParameters, SecuritySignatureFactoryEcBc<S> signatureFactory, SecurityHashConfig hashConfig,
      SecurityRandomFactory randomFactory) {

    this(ecParameters, signatureFactory, hashConfig, randomFactory, SecurityProvider.of(BouncyCastle.getProvider()));
  }

  private SecurityAccessEcBc(ECParameterSpec ecParameters, SecuritySignatureFactoryEcBc<S> signatureFactory, SecurityHashConfig hashConfig,
      SecurityRandomFactory randomFactory, SecurityProvider provider) {

    this(ecParameters, new SecuritySignatureConfig<>(signatureFactory, hashConfig, SecurityAlgorithmEcDsa.ALGORITHM_ECDSA, provider),
        new SecurityAsymmetricCryptorConfigEcies<>(provider), randomFactory);
  }

  @Override
  public SecurityAsymmetricKeyCreatorEcBc newKeyCreator() {

    return new SecurityAsymmetricKeyCreatorEcBc(this.ecParameters, this.randomFactory);
  }

}
