package io.github.mmm.crypto.asymmetric.sign.ec.bc;

import java.math.BigInteger;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;

import io.github.mmm.crypto.asymmetric.access.ec.bc.CryptoEllipticCurveBc;
import io.github.mmm.crypto.asymmetric.sign.SignatureBinary;
import io.github.mmm.crypto.asymmetric.sign.SignatureFactory;

/// Implementation of [SignatureFactory] for [SignatureEcBc].
///
/// @param <S> type of [SignatureBinary].
/// @since 1.0.0
public abstract class SignatureFactoryEcBc<S extends SignatureEcBc> implements SignatureFactory<S> {

  /// The [elliptic curve][CryptoEllipticCurveBc].
  protected final CryptoEllipticCurveBc curve;

  /// The constructor.
  ///
  /// @param curve the [elliptic curve][CryptoEllipticCurveBc].
  public SignatureFactoryEcBc(CryptoEllipticCurveBc curve) {

    super();
    this.curve = curve;
  }

  /// @param r the value [r][SignatureEcBc#getR()].
  /// @param s the value [s][SignatureEcBc#getS()].
  /// @param message the signed message (hash).
  /// @param publicKey the [BCECPublicKey] that was used to sign the message.
  /// @return the signature.
  public abstract S create(BigInteger r, BigInteger s, byte[] message, BCECPublicKey publicKey);

}
