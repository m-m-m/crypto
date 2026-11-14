package io.github.mmm.crypto.symmetric.key.pbe;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import io.github.mmm.crypto.provider.SecurityProvider;
import io.github.mmm.crypto.symmetric.key.SymmetricKeyConfig;
import io.github.mmm.crypto.symmetric.key.spec.SymmetricKeySpecFactoryImplPbe;

/// [SymmetricKeyConfig] for PBE (Password Based Encryption).
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public class SymmetricKeyConfigPbe extends SymmetricKeyConfig {

  private static final byte[] SALT = new byte[] { (byte) 0x0fc, (byte) 0x007, (byte) 0x0cf, (byte) 0x01c, (byte) 0x003, (byte) 0x00b,
  (byte) 0x0ff, (byte) 0x020, (byte) 0x021, (byte) 0x0aa, (byte) 0x027, (byte) 0x0b3, (byte) 0x091, (byte) 0x0e6, (byte) 0x0c5,
  (byte) 0x069, (byte) 0x0ee, (byte) 0x08b, (byte) 0x017, (byte) 0x032 };

  /// The constructor.
  ///
  /// @param algorithm the [algorithm][#getAlgorithm()].
  /// @param keyLength the [key length][#getKeyLength()] in bits.
  public SymmetricKeyConfigPbe(String algorithm, int keyLength) {

    this(algorithm, keyLength, 65536, SALT);
  }

  /// The constructor.
  ///
  /// @param algorithm the [algorithm][#getAlgorithm()].
  /// @param provider the [SecurityProvider].
  /// @param keyLength the [key length][#getKeyLength()] in bits.
  public SymmetricKeyConfigPbe(String algorithm, SecurityProvider provider, int keyLength) {

    this(algorithm, provider, keyLength, 65536, SALT);
  }

  /// The constructor.
  ///
  /// @param algorithm the [algorithm][#getAlgorithm()].
  /// @param keyLength the [key length][#getKeyLength()] in bits.
  /// @param iterationCount the [iteration count][io.github.mmm.crypto.AbstractGetIterationCount#getIterationCount()].
  public SymmetricKeyConfigPbe(String algorithm, int keyLength, int iterationCount) {

    this(algorithm, keyLength, iterationCount, SALT);
  }

  /// The constructor.
  ///
  /// @param algorithm the [algorithm][#getAlgorithm()].
  /// @param keyLength the [key length][#getKeyLength()] in bits.
  /// @param iterationCount the [iteration count][io.github.mmm.crypto.AbstractGetIterationCount#getIterationCount()].
  /// @param salt the [salt][javax.crypto.spec.PBEKeySpec#getSalt()].
  public SymmetricKeyConfigPbe(String algorithm, int keyLength, int iterationCount, byte[] salt) {

    this(algorithm, null, keyLength, iterationCount, salt);
  }

  /// The constructor.
  ///
  /// @param algorithm the [algorithm][#getAlgorithm()].
  /// @param provider the [SecurityProvider].
  /// @param keyLength the [key length][#getKeyLength()] in bits.
  /// @param iterationCount the [iteration count][io.github.mmm.crypto.AbstractGetIterationCount#getIterationCount()].
  /// @param salt the [salt][javax.crypto.spec.PBEKeySpec#getSalt()].
  public SymmetricKeyConfigPbe(String algorithm, SecurityProvider provider, int keyLength, int iterationCount, byte[] salt) {

    super(algorithm, provider, keyLength, new SymmetricKeySpecFactoryImplPbe(salt, iterationCount, keyLength));
  }

  @Override
  public int getKeyLength(SecretKey key, SecretKeyFactory keyFactory) {

    return 0;
    // try {

    // if (key instanceof org.bouncycastle.jcajce.provider.symmetric.util.BCPBEKey) {
    // org.bouncycastle.jcajce.provider.symmetric.util.BCPBEKey pbeKey =
    // (org.bouncycastle.jcajce.provider.symmetric.util.BCPBEKey) key;
    // return pbeKey.getKeySize();
    // }
    // PBEKeySpec keySpec = (PBEKeySpec) keyFactory.getKeySpec(key, PBEKeySpec.class);
    // return keySpec.getKeyLength();
    // } catch (InvalidKeySpecException e) {
    // throw new IllegalStateException(e);
    // }
  }

}
