package net.sf.mmm.security.api.asymmetric.sign.ec.bc;

import java.math.BigInteger;

import net.sf.mmm.security.api.asymmetric.access.ec.bc.SecurityEllipticCurveBc;
import net.sf.mmm.security.api.asymmetric.sign.SecuritySignatureFactory;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;

/**
 * Implementation of {@link SecuritySignatureFactory} for {@link SecuritySignatureEcBcWithRecoveryId}.
 *
 * @since 1.0.0
 */
public class SecuritySignatureFactoryEcBcWithRecoveryId extends SecuritySignatureFactoryEcBc<SecuritySignatureEcBcWithRecoveryId> {

  private static final byte DEFAULT_RECOVERY_OFFSET = (byte) (SecuritySignatureEcBcWithRecoveryId.BITCOIN_RECOVERY_OFFSET
      + SecuritySignatureEcBcWithRecoveryId.BITCOIN_COMPRESSED_OFFSET);

  private final byte recoveryOffset;

  /**
   * The constructor.
   *
   * @param curve the {@link SecurityEllipticCurveBc elliptic curve}.
   */
  public SecuritySignatureFactoryEcBcWithRecoveryId(SecurityEllipticCurveBc curve) {

    this(curve, DEFAULT_RECOVERY_OFFSET);
  }

  /**
   * The constructor.
   *
   * @param curve the {@link SecurityEllipticCurveBc elliptic curve}.
   * @param recoveryOffset the {@link SecuritySignatureEcBcWithRecoveryId#getRecoveryOffset() recovery offset}.
   */
  public SecuritySignatureFactoryEcBcWithRecoveryId(SecurityEllipticCurveBc curve, byte recoveryOffset) {

    super(curve);
    this.recoveryOffset = recoveryOffset;
  }

  @Override
  public SecuritySignatureEcBcWithRecoveryId createSignature(byte[] data) {

    return new SecuritySignatureEcBcWithRecoveryId(this.curve, data, this.recoveryOffset);
  }

  @Override
  public SecuritySignatureEcBcWithRecoveryId create(BigInteger r, BigInteger s, byte[] message, BCECPublicKey publicKey) {

    return SecuritySignatureEcBcWithRecoveryId.of(this.curve, r, s, message, publicKey, this.recoveryOffset);
  }

}
