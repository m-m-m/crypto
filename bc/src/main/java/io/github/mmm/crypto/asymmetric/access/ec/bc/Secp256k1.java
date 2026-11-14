/* Copyright (c) The m-m-m Team, Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0 */
package io.github.mmm.crypto.asymmetric.access.ec.bc;

import java.math.BigInteger;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;

import io.github.mmm.crypto.asymmetric.crypt.ec.AsymmetricCryptorConfigEcIes;
import io.github.mmm.crypto.asymmetric.sign.SignatureBinary;
import io.github.mmm.crypto.asymmetric.sign.SignatureConfig;
import io.github.mmm.crypto.asymmetric.sign.ec.bc.SignatureEcBc;
import io.github.mmm.crypto.asymmetric.sign.ec.bc.SignatureEcBcPlain;
import io.github.mmm.crypto.asymmetric.sign.ec.bc.SignatureEcBcWithRecoveryId;
import io.github.mmm.crypto.asymmetric.sign.ec.bc.SignatureFactoryEcBc;
import io.github.mmm.crypto.asymmetric.sign.ec.bc.SignatureFactoryEcBcPlain;
import io.github.mmm.crypto.asymmetric.sign.ec.bc.SignatureFactoryEcBcWithRecoveryId;
import io.github.mmm.crypto.hash.HashConfig;
import io.github.mmm.crypto.random.RandomFactory;

/// [AsymmetricAccessEcBc] for [SecP256K1Curve].
///
/// @param <S> type of [SignatureBinary].
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public class Secp256k1<S extends SignatureEcBc> extends AsymmetricAccessEcBc<S> {

  /// The [curve name][CryptoEllipticCurveBc#getCurveName()].
  public static final String CURVE_NAME = "secp256k1";

  /// The [elliptic curve][CryptoEllipticCurveBc].
  public static final CryptoEllipticCurveBc CURVE = new CryptoEllipticCurveBc(CURVE_NAME) {
    @Override
    protected BigInteger determineCurveQ() {

      SecP256K1Curve curve = (SecP256K1Curve) getEcParameters().getCurve();
      return curve.getQ();
    }
  };

  /// The constructor.
  ///
  /// @param signatureConfig the [SignatureConfig].
  /// @param cryptorConfig the [AsymmetricCryptorConfigEcIes].
  /// @param randomFactory the optional [RandomFactory].
  public Secp256k1(SignatureConfig<S> signatureConfig,
      AsymmetricCryptorConfigEcIes<BCECPrivateKey, BCECPublicKey> cryptorConfig, RandomFactory randomFactory) {

    super(CURVE.getEcParameters(), signatureConfig, cryptorConfig, randomFactory);
  }

  /// The constructor.
  ///
  /// @param signatureFactory the [SignatureFactoryEcBc].
  /// @param hashConfig the [HashConfig] for the hash used for signatures.
  /// @param randomFactory the [RandomFactory].
  public Secp256k1(SignatureFactoryEcBc<S> signatureFactory, HashConfig hashConfig, RandomFactory randomFactory) {

    super(CURVE.getEcParameters(), signatureFactory, hashConfig, randomFactory);
  }

  /// @param hashAlgorithm the [algorithm][HashConfig#getAlgorithm()] for the hash used for signatures.
  /// @return a [Secp256k1] instance for default signature.
  public static Secp256k1<SignatureEcBcPlain> ofPlain(String hashAlgorithm) {

    return ofPlain(new HashConfig(hashAlgorithm));
  }

  /// @param hashConfig the [HashConfig] for the hash used for signatures.
  /// @return a [Secp256k1] instance for default signature.
  public static Secp256k1<SignatureEcBcPlain> ofPlain(HashConfig hashConfig) {

    return of(new SignatureFactoryEcBcPlain(CURVE), hashConfig, null);
  }

  /// @param hashAlgorithm the [algorithm][HashConfig#getAlgorithm()] for the hash used for signatures.
  /// @return a [Secp256k1] instance for bitcoin signature.
  public static Secp256k1<SignatureEcBcWithRecoveryId> ofRecoveryId(String hashAlgorithm) {

    return ofRecoveryId(new HashConfig(hashAlgorithm));
  }

  /// @param hashConfig the [HashConfig] for the hash used for signatures.
  /// @return a [Secp256k1] instance for bitcoin signature.
  public static Secp256k1<SignatureEcBcWithRecoveryId> ofRecoveryId(HashConfig hashConfig) {

    return of(new SignatureFactoryEcBcWithRecoveryId(CURVE), hashConfig, null);
  }

  /// @param <S> type of [signature][SignatureEcBc].
  /// @param signatureFactory the [SignatureFactoryEcBc].
  /// @param hashConfig the [HashConfig] for the hash used for signatures.
  /// @param randomFactory the [RandomFactory].
  /// @return a [Secp256k1] instance for the given parameters.
  public static <S extends SignatureEcBc> Secp256k1<S> of(SignatureFactoryEcBc<S> signatureFactory,
      HashConfig hashConfig, RandomFactory randomFactory) {

    return new Secp256k1<>(signatureFactory, hashConfig, randomFactory);
  }

}
