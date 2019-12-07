package io.github.mmm.crypto.asymmetric.sign.ec.bc;

import java.math.BigInteger;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;

import io.github.mmm.crypto.asymmetric.access.ec.bc.CryptoEllipticCurveBc;

/**
 * Implementation of {@link io.github.mmm.crypto.asymmetric.sign.SignatureFactory} for
 * {@link SignatureEcBcWithRecoveryId}.
 *
 * @since 1.0.0
 */
public class SignatureFactoryEcBcWithRecoveryId extends SignatureFactoryEcBc<SignatureEcBcWithRecoveryId> {

  private static final byte DEFAULT_RECOVERY_OFFSET = (byte) (SignatureEcBcWithRecoveryId.BITCOIN_RECOVERY_OFFSET
      + SignatureEcBcWithRecoveryId.BITCOIN_COMPRESSED_OFFSET);

  private final byte recoveryOffset;

  /**
   * The constructor.
   *
   * @param curve the {@link CryptoEllipticCurveBc elliptic curve}.
   */
  public SignatureFactoryEcBcWithRecoveryId(CryptoEllipticCurveBc curve) {

    this(curve, DEFAULT_RECOVERY_OFFSET);
  }

  /**
   * The constructor.
   *
   * @param curve the {@link CryptoEllipticCurveBc elliptic curve}.
   * @param recoveryOffset the {@link SignatureEcBcWithRecoveryId#getRecoveryOffset() recovery offset}.
   */
  public SignatureFactoryEcBcWithRecoveryId(CryptoEllipticCurveBc curve, byte recoveryOffset) {

    super(curve);
    this.recoveryOffset = recoveryOffset;
  }

  @Override
  public SignatureEcBcWithRecoveryId createSignature(byte[] data) {

    return new SignatureEcBcWithRecoveryId(this.curve, data, this.recoveryOffset);
  }

  @Override
  public SignatureEcBcWithRecoveryId create(BigInteger r, BigInteger s, byte[] message, BCECPublicKey publicKey) {

    return SignatureEcBcWithRecoveryId.of(this.curve, r, s, message, publicKey, this.recoveryOffset);
  }

}
