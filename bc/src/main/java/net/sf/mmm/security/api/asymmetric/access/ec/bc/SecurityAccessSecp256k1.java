/* Copyright (c) The m-m-m Team, Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0 */
package net.sf.mmm.security.api.asymmetric.access.ec.bc;

import java.math.BigInteger;

import net.sf.mmm.security.api.asymmetric.crypt.ec.SecurityAsymmetricCryptorConfigEcies;
import net.sf.mmm.security.api.asymmetric.sign.SecuritySignature;
import net.sf.mmm.security.api.asymmetric.sign.SecuritySignatureConfig;
import net.sf.mmm.security.api.asymmetric.sign.ec.bc.SecuritySignatureEcBc;
import net.sf.mmm.security.api.asymmetric.sign.ec.bc.SecuritySignatureEcBcPlain;
import net.sf.mmm.security.api.asymmetric.sign.ec.bc.SecuritySignatureEcBcWithRecoveryId;
import net.sf.mmm.security.api.asymmetric.sign.ec.bc.SecuritySignatureFactoryEcBc;
import net.sf.mmm.security.api.asymmetric.sign.ec.bc.SecuritySignatureFactoryEcBcPlain;
import net.sf.mmm.security.api.asymmetric.sign.ec.bc.SecuritySignatureFactoryEcBcWithRecoveryId;
import net.sf.mmm.security.api.hash.SecurityHashConfig;
import net.sf.mmm.security.api.random.SecurityRandomFactory;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;

/**
 * {@link SecurityAccessEcBc} for {@link SecP256K1Curve}.
 *
 * @param <S> type of {@link SecuritySignature}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityAccessSecp256k1<S extends SecuritySignatureEcBc> extends SecurityAccessEcBc<S> {

  /** The {@link SecurityEllipticCurveBc#getCurveName() curve name}. */
  public static final String CURVE_NAME = "secp256k1";

  /** The {@link SecurityEllipticCurveBc elliptic curve}. */
  public static final SecurityEllipticCurveBc CURVE = new SecurityEllipticCurveBc(CURVE_NAME) {
    @Override
    protected BigInteger determineCurveQ() {

      SecP256K1Curve curve = (SecP256K1Curve) getEcParameters().getCurve();
      return curve.getQ();
    }
  };

  /**
   * The constructor.
   *
   * @param signatureConfig the {@link SecuritySignatureConfig}.
   * @param cryptorConfig the {@link SecurityAsymmetricCryptorConfigEcies}.
   * @param randomFactory the optional {@link SecurityRandomFactory}.
   */
  public SecurityAccessSecp256k1(SecuritySignatureConfig<S> signatureConfig,
      SecurityAsymmetricCryptorConfigEcies<BCECPrivateKey, BCECPublicKey> cryptorConfig, SecurityRandomFactory randomFactory) {

    super(CURVE.getEcParameters(), signatureConfig, cryptorConfig, randomFactory);
  }

  /**
   * The constructor.
   *
   * @param signatureFactory the {@link SecuritySignatureFactoryEcBc}.
   * @param hashConfig the {@link SecurityHashConfig} for the hash used for signatures.
   * @param randomFactory the {@link SecurityRandomFactory}.
   */
  public SecurityAccessSecp256k1(SecuritySignatureFactoryEcBc<S> signatureFactory, SecurityHashConfig hashConfig,
      SecurityRandomFactory randomFactory) {

    super(CURVE.getEcParameters(), signatureFactory, hashConfig, randomFactory);
  }

  /**
   * @param hashAlgorithm the {@link SecurityHashConfig#getAlgorithm() algorithm} for the hash used for signatures.
   * @return a {@link SecurityAccessSecp256k1} instance for default signature.
   */
  public static SecurityAccessSecp256k1<SecuritySignatureEcBcPlain> ofPlain(String hashAlgorithm) {

    return ofPlain(new SecurityHashConfig(hashAlgorithm));
  }

  /**
   * @param hashConfig the {@link SecurityHashConfig} for the hash used for signatures.
   * @return a {@link SecurityAccessSecp256k1} instance for default signature.
   */
  public static SecurityAccessSecp256k1<SecuritySignatureEcBcPlain> ofPlain(SecurityHashConfig hashConfig) {

    return of(new SecuritySignatureFactoryEcBcPlain(CURVE), hashConfig, null);
  }

  /**
   * @param hashAlgorithm the {@link SecurityHashConfig#getAlgorithm() algorithm} for the hash used for signatures.
   * @return a {@link SecurityAccessSecp256k1} instance for bitcoin signature.
   */
  public static SecurityAccessSecp256k1<SecuritySignatureEcBcWithRecoveryId> ofRecoveryId(String hashAlgorithm) {

    return ofRecoveryId(new SecurityHashConfig(hashAlgorithm));
  }

  /**
   * @param hashConfig the {@link SecurityHashConfig} for the hash used for signatures.
   * @return a {@link SecurityAccessSecp256k1} instance for bitcoin signature.
   */
  public static SecurityAccessSecp256k1<SecuritySignatureEcBcWithRecoveryId> ofRecoveryId(SecurityHashConfig hashConfig) {

    return of(new SecuritySignatureFactoryEcBcWithRecoveryId(CURVE), hashConfig, null);
  }

  /**
   * @param <S> type of {@link SecuritySignatureEcBc signature}.
   * @param signatureFactory the {@link SecuritySignatureFactoryEcBc}.
   * @param hashConfig the {@link SecurityHashConfig} for the hash used for signatures.
   * @param randomFactory the {@link SecurityRandomFactory}.
   * @return a {@link SecurityAccessSecp256k1} instance for the given parameters.
   */
  public static <S extends SecuritySignatureEcBc> SecurityAccessSecp256k1<S> of(SecuritySignatureFactoryEcBc<S> signatureFactory,
      SecurityHashConfig hashConfig, SecurityRandomFactory randomFactory) {

    return new SecurityAccessSecp256k1<>(signatureFactory, hashConfig, randomFactory);
  }

}
