package io.github.mmm.crypto.crypt;

import io.github.mmm.crypto.algorithm.CryptoAlgorithmConfig;
import io.github.mmm.crypto.provider.SecurityProvider;

/// Class of an [algorithm configuration][CryptoAlgorithmConfig] for
/// [encryption][Encryptor#crypt(byte[], boolean)] and [decryption][Decryptor#crypt(byte[], boolean)].
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public class CryptorConfig extends CryptoAlgorithmConfig implements AbstractGetNonceSize {

  private final CipherTransformation transformation;

  private final int nonceSize;

  /// The constructor.
  ///
  /// @param transformation the [transfomation][#getTransformation()] for the [javax.crypto.Cipher].
  /// @param provider the [SecurityProvider].
  /// @param nonceSize the [nonce size][#getNonceSize()].
  public CryptorConfig(CipherTransformation transformation, SecurityProvider provider, int nonceSize) {

    super(transformation.getTransformation(), provider);
    this.transformation = transformation;
    this.nonceSize = nonceSize;
  }

  /// @return the [CipherTransformation].
  public CipherTransformation getTransformation() {

    return this.transformation;
  }

  /// This method returns `false` by default. You may override this method to create a random nonce individually
  /// but only if you know exactly what you are doing and what are the details about the cryptographic algorithm.
  ///
  /// @return `true` if the [nonce][#getNonceSize()] should be created individually from
  ///         [java.security.SecureRandom], `false` to get from [initialization vector][javax.crypto.Cipher#getIV()].
  public boolean isCreateRandomNonce() {

    return false;
  }

  @Override
  public final int getNonceSize() {

    return this.nonceSize;
  }

}
