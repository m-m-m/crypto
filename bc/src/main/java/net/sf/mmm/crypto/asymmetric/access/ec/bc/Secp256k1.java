/* Copyright (c) The m-m-m Team, Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0 */
package net.sf.mmm.crypto.asymmetric.access.ec.bc;

import java.math.BigInteger;

import net.sf.mmm.crypto.asymmetric.crypt.ec.AsymmetricCryptorConfigEcIes;
import net.sf.mmm.crypto.asymmetric.sign.SignatureBinary;
import net.sf.mmm.crypto.asymmetric.sign.SignatureConfig;
import net.sf.mmm.crypto.asymmetric.sign.ec.bc.SignatureEcBc;
import net.sf.mmm.crypto.asymmetric.sign.ec.bc.SignatureEcBcPlain;
import net.sf.mmm.crypto.asymmetric.sign.ec.bc.SignatureEcBcWithRecoveryId;
import net.sf.mmm.crypto.asymmetric.sign.ec.bc.SignatureFactoryEcBc;
import net.sf.mmm.crypto.asymmetric.sign.ec.bc.SignatureFactoryEcBcPlain;
import net.sf.mmm.crypto.asymmetric.sign.ec.bc.SignatureFactoryEcBcWithRecoveryId;
import net.sf.mmm.crypto.hash.HashConfig;
import net.sf.mmm.crypto.random.RandomFactory;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;

/**
 * {@link AsymmetricAccessEcBc} for {@link SecP256K1Curve}.
 *
 * @param <S> type of {@link SignatureBinary}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class Secp256k1<S extends SignatureEcBc> extends AsymmetricAccessEcBc<S> {

  /** The {@link CryptoEllipticCurveBc#getCurveName() curve name}. */
  public static final String CURVE_NAME = "secp256k1";

  /** The {@link CryptoEllipticCurveBc elliptic curve}. */
  public static final CryptoEllipticCurveBc CURVE = new CryptoEllipticCurveBc(CURVE_NAME) {
    @Override
    protected BigInteger determineCurveQ() {

      SecP256K1Curve curve = (SecP256K1Curve) getEcParameters().getCurve();
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
  public Secp256k1(SignatureConfig<S> signatureConfig,
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
  public Secp256k1(SignatureFactoryEcBc<S> signatureFactory, HashConfig hashConfig, RandomFactory randomFactory) {

    super(CURVE.getEcParameters(), signatureFactory, hashConfig, randomFactory);
  }

  /**
   * @param hashAlgorithm the {@link HashConfig#getAlgorithm() algorithm} for the hash used for signatures.
   * @return a {@link Secp256k1} instance for default signature.
   */
  public static Secp256k1<SignatureEcBcPlain> ofPlain(String hashAlgorithm) {

    return ofPlain(new HashConfig(hashAlgorithm));
  }

  /**
   * @param hashConfig the {@link HashConfig} for the hash used for signatures.
   * @return a {@link Secp256k1} instance for default signature.
   */
  public static Secp256k1<SignatureEcBcPlain> ofPlain(HashConfig hashConfig) {

    return of(new SignatureFactoryEcBcPlain(CURVE), hashConfig, null);
  }

  /**
   * @param hashAlgorithm the {@link HashConfig#getAlgorithm() algorithm} for the hash used for signatures.
   * @return a {@link Secp256k1} instance for bitcoin signature.
   */
  public static Secp256k1<SignatureEcBcWithRecoveryId> ofRecoveryId(String hashAlgorithm) {

    return ofRecoveryId(new HashConfig(hashAlgorithm));
  }

  /**
   * @param hashConfig the {@link HashConfig} for the hash used for signatures.
   * @return a {@link Secp256k1} instance for bitcoin signature.
   */
  public static Secp256k1<SignatureEcBcWithRecoveryId> ofRecoveryId(HashConfig hashConfig) {

    return of(new SignatureFactoryEcBcWithRecoveryId(CURVE), hashConfig, null);
  }

  /**
   * @param <S> type of {@link SignatureEcBc signature}.
   * @param signatureFactory the {@link SignatureFactoryEcBc}.
   * @param hashConfig the {@link HashConfig} for the hash used for signatures.
   * @param randomFactory the {@link RandomFactory}.
   * @return a {@link Secp256k1} instance for the given parameters.
   */
  public static <S extends SignatureEcBc> Secp256k1<S> of(SignatureFactoryEcBc<S> signatureFactory,
      HashConfig hashConfig, RandomFactory randomFactory) {

    return new Secp256k1<>(signatureFactory, hashConfig, randomFactory);
  }

}
