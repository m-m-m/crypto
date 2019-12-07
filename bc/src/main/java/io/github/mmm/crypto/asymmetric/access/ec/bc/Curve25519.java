/* Copyright (c) The m-m-m Team, Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0 */
package io.github.mmm.crypto.asymmetric.access.ec.bc;

import java.math.BigInteger;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;

import io.github.mmm.crypto.asymmetric.crypt.ec.AsymmetricCryptorConfigEcIes;
import io.github.mmm.crypto.asymmetric.sign.SignatureConfig;
import io.github.mmm.crypto.asymmetric.sign.ec.bc.SignatureEcBc;
import io.github.mmm.crypto.asymmetric.sign.ec.bc.SignatureEcBcPlain;
import io.github.mmm.crypto.asymmetric.sign.ec.bc.SignatureEcBcWithRecoveryId;
import io.github.mmm.crypto.asymmetric.sign.ec.bc.SignatureFactoryEcBc;
import io.github.mmm.crypto.asymmetric.sign.ec.bc.SignatureFactoryEcBcPlain;
import io.github.mmm.crypto.asymmetric.sign.ec.bc.SignatureFactoryEcBcWithRecoveryId;
import io.github.mmm.crypto.hash.HashConfig;
import io.github.mmm.crypto.random.RandomFactory;

/**
 * {@link AsymmetricAccessEcBc} for {@code Curve25519}.
 *
 * @param <S> type of {@link SignatureEcBc}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class Curve25519<S extends SignatureEcBc> extends AsymmetricAccessEcBc<S> {

  /** The {@link CryptoEllipticCurveBc#getCurveName() curve name}. */
  public static final String CURVE_NAME = "curve25519";

  /** The {@link CryptoEllipticCurveBc elliptic curve}. */
  public static final CryptoEllipticCurveBc CURVE = new CryptoEllipticCurveBc(CURVE_NAME) {
    @Override
    protected BigInteger determineCurveQ() {

      org.bouncycastle.math.ec.custom.djb.Curve25519 curve = (org.bouncycastle.math.ec.custom.djb.Curve25519) getEcParameters()
          .getCurve();
      return curve.getQ();
    }
  };

  /**
   * The constructor.
   *
   * @param signatureConfig the {@link SignatureConfig}.
   * @param cryptorConfig the {@link AsymmetricCryptorConfigEcIes}.
   * @param randomFactory the optional {@link RandomFactory}.
   */
  public Curve25519(SignatureConfig<S> signatureConfig,
      AsymmetricCryptorConfigEcIes<BCECPrivateKey, BCECPublicKey> cryptorConfig, RandomFactory randomFactory) {

    super(CURVE.getEcParameters(), signatureConfig, cryptorConfig, randomFactory);
  }

  /**
   * The constructor.
   *
   * @param signatureFactory the {@link SignatureFactoryEcBc}.
   * @param hashConfig the {@link HashConfig} for the hash used for signatures.
   * @param randomFactory the {@link RandomFactory}.
   */
  public Curve25519(SignatureFactoryEcBc<S> signatureFactory, HashConfig hashConfig, RandomFactory randomFactory) {

    super(CURVE.getEcParameters(), signatureFactory, hashConfig, randomFactory);
  }

  /**
   * @param hashAlgorithm the {@link HashConfig#getAlgorithm() algorithm} for the hash used for signatures.
   * @return a {@link Curve25519} instance for plain signature.
   */
  public static Curve25519<SignatureEcBcPlain> ofPlain(String hashAlgorithm) {

    return ofPlain(new HashConfig(hashAlgorithm));
  }

  /**
   * @param hashConfig the {@link HashConfig} for the hash used for signatures.
   * @return a {@link Curve25519} instance for plain signature.
   */
  public static Curve25519<SignatureEcBcPlain> ofPlain(HashConfig hashConfig) {

    return of(new SignatureFactoryEcBcPlain(CURVE), hashConfig, null);
  }

  /**
   * @param hashAlgorithm the {@link HashConfig#getAlgorithm() algorithm} for the hash used for signatures.
   * @return a {@link Curve25519} instance for signature with {@link SignatureEcBcWithRecoveryId#getRecoveryId()
   *         recovery ID}.
   */
  public static Curve25519<SignatureEcBcWithRecoveryId> ofRecoveryId(String hashAlgorithm) {

    return ofRecoveryId(new HashConfig(hashAlgorithm));
  }

  /**
   * @param hashConfig the {@link HashConfig} for the hash used for signatures.
   * @return a {@link Curve25519} instance for signature with {@link SignatureEcBcWithRecoveryId#getRecoveryId()
   *         recovery ID}.
   */
  public static Curve25519<SignatureEcBcWithRecoveryId> ofRecoveryId(HashConfig hashConfig) {

    return of(new SignatureFactoryEcBcWithRecoveryId(CURVE), hashConfig, null);
  }

  /**
   * @param <S> type of {@link SignatureFactoryEcBc signature}.
   * @param signatureFactory the {@link SignatureFactoryEcBc}.
   * @param hashConfig the {@link HashConfig} for the hash used for signatures.
   * @param randomFactory the {@link RandomFactory}.
   * @return a {@link Curve25519} instance for the given parameters.
   */
  public static <S extends SignatureEcBc> Curve25519<S> of(SignatureFactoryEcBc<S> signatureFactory,
      HashConfig hashConfig, RandomFactory randomFactory) {

    return new Curve25519<>(signatureFactory, hashConfig, randomFactory);
  }

}
