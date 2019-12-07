/* Copyright (c) The m-m-m Team, Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0 */
package io.github.mmm.crypto.asymmetric.access.ec.bc;

import java.nio.charset.StandardCharsets;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.junit.jupiter.api.Test;

import io.github.mmm.binary.BinaryType;
import io.github.mmm.crypto.CryptoBinaryFormat;
import io.github.mmm.crypto.asymmetric.key.ec.bc.AsymmetricKeyCreatorEcBc;
import io.github.mmm.crypto.asymmetric.key.ec.bc.AsymmetricKeyPairEcBc;
import io.github.mmm.crypto.asymmetric.sign.ec.bc.SignatureEcBcPlain;
import io.github.mmm.crypto.asymmetric.sign.ec.bc.SignatureEcBcWithRecoveryId;
import io.github.mmm.crypto.hash.HashConfig;
import io.github.mmm.crypto.hash.sha2.Sha256;

/**
 * Test of {@link Secp256k1}.
 */
@SuppressWarnings({ "rawtypes" })
public class Secp256k1Test extends AsymmetricAccessTest {

  /**
   * Basic/generic test of {@link Secp256k1#ofPlain(String)}.
   */
  @Test
  public void testSecp256k1() {

    // given
    Secp256k1 secp256k1 = Secp256k1.ofPlain(Sha256.SHA_256);
    assertThat(secp256k1.getSignatureConfig().getHashConfig().getAlgorithm()).isEqualTo("SHA-256")
        .isEqualTo(Sha256.ALGORITHM_SHA_256);
    assertThat(secp256k1.getSignatureConfig().getSignatureAlgorithm().getHashAlgorithm()).isEqualTo("SHA-256");
    assertThat(secp256k1.getSignatureConfig().getSignatureAlgorithm().getSigningAlgorithm()).isEqualTo("ECDSA");
    assertThat(secp256k1.getCryptorConfig().getAlgorithm()).isEqualTo("ECIES");
    assertThat(secp256k1.newKeyCreator().getKeyLength()).isEqualTo(256);

    // when + then
    verify(secp256k1, 99);
  }

  @Override
  protected int getPrivateKeyCompactMinLength() {

    return 31;
  }

  @Override
  protected int getPrivateKeyCompactLength() {

    return 33;
  }

  @Override
  protected int getPrivateKeyEncodedLength() {

    return 591;
  }

  @Override
  protected int getPublicKeyCompactLength() {

    return 33;
  }

  @Override
  protected int getPublicKeyEncodedLength() {

    return 311;
  }

  /**
   * Test of {@link Secp256k1#ofRecoveryId(HashConfig)} with official examples from BitCoin.
   */
  @Test
  public void testSecp256k1KeyPairFromBitcoin() {

    Secp256k1<SignatureEcBcWithRecoveryId> secp256k1 = Secp256k1
        .ofRecoveryId(new HashConfig(Sha256.ALGORITHM_SHA_256, 1));
    AsymmetricKeyCreatorEcBc keyCreator = secp256k1.newKeyCreator();
    // https://en.bitcoin.it/wiki/Private_key
    // https://privatekeys.pw/key/5Kb8kLf9zgWQnogidDA76MzPL6TsZZY36hWXMssSzNydYXYB9KF

    // private key
    String privateKeyHex = "e9873d79c6d87dc0fb6a5778633389f4453213303da61f20bd67fc233aa33262";
    byte[] privateKeyBytes = BinaryType.parseHex(privateKeyHex);
    BCECPrivateKey privateKey = keyCreator.createPrivateKey(privateKeyBytes);
    assertThat(BinaryType.formatHex(keyCreator.asData(privateKey, CryptoBinaryFormat.FORMAT_COMPACT)))
        .isEqualTo(privateKeyHex);

    // public key
    String publicKeyHex = "02588d202afcc1ee4ab5254c7847ec25b9a135bbda0f2bc69ee1a714749fd77dc9";
    byte[] publicKeyBytes = BinaryType.parseHex(publicKeyHex);
    BCECPublicKey publicKey = keyCreator.createPublicKey(publicKeyBytes);
    assertThat(BinaryType.formatHex(keyCreator.asData(publicKey, CryptoBinaryFormat.FORMAT_COMPACT)))
        .isEqualTo(publicKeyHex);

    // key pair (generate public key from private key)
    // ECKey key = new ECKey(privKey, true);
    // byte[] pubKey = key.getPubKey();
    AsymmetricKeyPairEcBc keyPair = keyCreator.createKeyPair(privateKeyBytes);
    publicKey = keyPair.getPublicKey();
    assertThat(BinaryType.formatHex(keyCreator.asData(publicKey, CryptoBinaryFormat.FORMAT_COMPACT)))
        .isEqualTo(publicKeyHex);

    byte[] data = "Hello World!".getBytes();
    byte[] hash = secp256k1.newHashCreator().hash(data, true);
    SignatureEcBcWithRecoveryId signature = secp256k1.getSignatureFactoryWithoutHash().newSigner(privateKey).sign(hash,
        false);
    String signatureHex = signature.formatHex();
    assertThat(signatureHex).isEqualTo(
        "1fd1601269aac7205e00dee3a99cd3d666505e0466c7791f4b097ac237360f67ef344e0875c6a1328fc37e0964d52c6d199e9e6b2eb3a3ab94fb3f9e73d1fdba88");
    boolean valid = secp256k1.getSignatureFactoryWithoutHash().newVerifier(publicKey).verify(hash, signature);
    assertThat(valid).isTrue();
    BCECPublicKey recoveredPublicKey = signature.recoverPublicKey(hash);
    assertThat(recoveredPublicKey).isEqualTo(publicKey);
    // recover signature to proper test initialization ...
    signature = secp256k1.createSignature(signature.getData());
    recoveredPublicKey = signature.recoverPublicKey(hash);
    assertThat(recoveredPublicKey).isEqualTo(publicKey);
    signature = secp256k1.createSignature(signature.getData());
    valid = secp256k1.getSignatureFactoryWithoutHash().newVerifier(publicKey).verify(hash, signature);
    assertThat(valid).isTrue();
  }

  /**
   * Advanced signature test of {@link Secp256k1#ofPlain(HashConfig)}.
   */
  @Test
  public void testSecp256k1Sign() {

    String privateKeyHex = "e9873d79c6d87dc0fb6a5778633389f4453213303da61f20bd67fc233aa33262";
    byte[] privateKeyBytes = BinaryType.parseHex(privateKeyHex);
    Secp256k1<SignatureEcBcPlain> secp256k1 = Secp256k1.ofPlain(new HashConfig(Sha256.ALGORITHM_SHA_256));
    AsymmetricKeyCreatorEcBc keyCreator = secp256k1.newKeyCreator();
    AsymmetricKeyPairEcBc keyPair = keyCreator.createKeyPair(privateKeyBytes);
    BCECPrivateKey privateKey = keyPair.getPrivateKey();
    BCECPublicKey publicKey = keyPair.getPublicKey();
    byte[] data = "Secret message".getBytes(StandardCharsets.UTF_8);

    SignatureEcBcPlain signature = secp256k1.newSigner(privateKey).sign(data, true);
    String sgn = signature.formatBase64();
    String expectedSignature = "DuIxpsDRrY5pSWHuKkxbDaRfgswM7MqgqyUJ1zLu3zFi44a4JU0Ons/79jRO1jsmemzKEsehY+QQxqdZ1+SStg==";
    assertThat(sgn).isEqualTo(expectedSignature);
    boolean valid = secp256k1.newVerifier(publicKey).verify(data, signature);
    assertThat(valid).isTrue();

    signature = secp256k1.getSignatureFactoryWithoutHash().newSigner(privateKey).sign(data, true);
    sgn = signature.formatBase64();
    expectedSignature = "b0yW5nSE/uTjG9CqT360w2IfWqvlg3S8zE6fDsnxCDwzGkk5oXB8wpfw9pL7AlZTrw3s+Ld6le6Mx8cb2MCqEg==";
    assertThat(sgn).isEqualTo(expectedSignature);
    valid = secp256k1.getSignatureFactoryWithoutHash().newVerifier(publicKey).verify(data, signature);
    assertThat(valid).isTrue();
  }

}
