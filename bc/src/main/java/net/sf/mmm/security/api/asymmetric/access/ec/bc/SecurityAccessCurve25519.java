/* Copyright (c) The m-m-m Team, Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0 */
package net.sf.mmm.security.api.asymmetric.access.ec.bc;

import java.math.BigInteger;

import net.sf.mmm.security.api.asymmetric.crypt.ec.SecurityAsymmetricCryptorConfigEcies;
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
import org.bouncycastle.math.ec.custom.djb.Curve25519;

/**
 * {@link SecurityAccessEcBc} for {@code Curve25519}.
 *
 * @param <S> type of {@link SecuritySignatureEcBc}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityAccessCurve25519<S extends SecuritySignatureEcBc> extends SecurityAccessEcBc<S> {

  /** The {@link SecurityEllipticCurveBc#getCurveName() curve name}. */
  public static final String CURVE_NAME = "curve25519";

  /** The {@link SecurityEllipticCurveBc elliptic curve}. */
  public static final SecurityEllipticCurveBc CURVE = new SecurityEllipticCurveBc(CURVE_NAME) {
    @Override
    protected BigInteger determineCurveQ() {

      Curve25519 curve = (Curve25519) getEcParameters().getCurve();
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
  public SecurityAccessCurve25519(SecuritySignatureConfig<S> signatureConfig,
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
  public SecurityAccessCurve25519(SecuritySignatureFactoryEcBc<S> signatureFactory, SecurityHashConfig hashConfig,
      SecurityRandomFactory randomFactory) {

    super(CURVE.getEcParameters(), signatureFactory, hashConfig, randomFactory);
  }

  /**
   * @param hashConfig the {@link SecurityHashConfig} for the hash used for signatures.
   * @return a {@link SecurityAccessCurve25519} instance for plain signature.
   */
  public static SecurityAccessCurve25519<SecuritySignatureEcBcPlain> ofPlain(SecurityHashConfig hashConfig) {

    return of(new SecuritySignatureFactoryEcBcPlain(CURVE), hashConfig, null);
  }

  /**
   * @param hashConfig the {@link SecurityHashConfig} for the hash used for signatures.
   * @return a {@link SecurityAccessCurve25519} instance for signature with
   *         {@link SecuritySignatureEcBcWithRecoveryId#getRecoveryId() recovery ID}.
   */
  public static SecurityAccessCurve25519<SecuritySignatureEcBcWithRecoveryId> ofRecoveryId(SecurityHashConfig hashConfig) {

    return of(new SecuritySignatureFactoryEcBcWithRecoveryId(CURVE), hashConfig, null);
  }

  /**
   * @param <S> type of {@link SecuritySignatureFactoryEcBc signature}.
   * @param signatureFactory the {@link SecuritySignatureFactoryEcBc}.
   * @param hashConfig the {@link SecurityHashConfig} for the hash used for signatures.
   * @param randomFactory the {@link SecurityRandomFactory}.
   * @return a {@link SecurityAccessCurve25519} instance for the given parameters.
   */
  public static <S extends SecuritySignatureEcBc> SecurityAccessCurve25519<S> of(SecuritySignatureFactoryEcBc<S> signatureFactory,
      SecurityHashConfig hashConfig, SecurityRandomFactory randomFactory) {

    return new SecurityAccessCurve25519<>(signatureFactory, hashConfig, randomFactory);
  }

}
