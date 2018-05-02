package net.sf.mmm.security.impl;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.time.Duration;
import java.time.Instant;

import org.assertj.core.api.Assertions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import net.sf.mmm.security.api.AbstractSecurityFactory;
import net.sf.mmm.security.api.SecurityBuilder;
import net.sf.mmm.security.api.SecurityFactoryBuilder;
import net.sf.mmm.security.api.algorithm.SecurityAlgorithmConfig;
import net.sf.mmm.security.api.algorithm.SecurityAlgorithmSha2;
import net.sf.mmm.security.api.cert.SecurityCertificate;
import net.sf.mmm.security.api.cert.SecurityCertificateConfig;
import net.sf.mmm.security.api.cert.SecurityCertificateConfigX509;
import net.sf.mmm.security.api.cert.SecurityCertificateCreator;
import net.sf.mmm.security.api.cert.SecurityCertificateDataBean;
import net.sf.mmm.security.api.cert.SecurityCertificatePath;
import net.sf.mmm.security.api.cert.SecurityCertificatePathGeneric;
import net.sf.mmm.security.api.crypt.SecurityCryptorConfig;
import net.sf.mmm.security.api.crypt.SecurityCryptorFactory;
import net.sf.mmm.security.api.crypt.SecurityDecryptor;
import net.sf.mmm.security.api.crypt.SecurityEncryptor;
import net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorConfig;
import net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorConfigBidirectional;
import net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorConfigCurve25519;
import net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorConfigEcies;
import net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorConfigPrivatePublic;
import net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorConfigPublicPrivate;
import net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorConfigRsa;
import net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorFactoryBidirectional;
import net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorFactoryPrivatePublic;
import net.sf.mmm.security.api.crypt.asymmetric.SecurityAsymmetricCryptorFactoryPublicPrivate;
import net.sf.mmm.security.api.crypt.symmetric.SecuritySymmetricCryptorConfig;
import net.sf.mmm.security.api.crypt.symmetric.SecuritySymmetricCryptorConfigAes;
import net.sf.mmm.security.api.crypt.symmetric.SecuritySymmetricCryptorFactory;
import net.sf.mmm.security.api.hash.SecurityHashConfig;
import net.sf.mmm.security.api.hash.SecurityHashConfigSha256;
import net.sf.mmm.security.api.hash.SecurityHashFactory;
import net.sf.mmm.security.api.io.SecurityFileResource;
import net.sf.mmm.security.api.key.SecurityKeySet;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyConfig;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyConfigEc;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyConfigRsa;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyCreator;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyFactory;
import net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyPair;
import net.sf.mmm.security.api.key.asymmetric.SecurityPrivateKey;
import net.sf.mmm.security.api.key.asymmetric.SecurityPublicKey;
import net.sf.mmm.security.api.key.store.SecurityKeyStore;
import net.sf.mmm.security.api.key.store.SecurityKeyStoreConfig;
import net.sf.mmm.security.api.key.store.SecurityKeyStoreConfigBks;
import net.sf.mmm.security.api.key.store.SecurityKeyStoreConfigJceks;
import net.sf.mmm.security.api.key.store.SecurityKeyStoreConfigJks;
import net.sf.mmm.security.api.key.store.SecurityKeyStoreConfigPkcs12;
import net.sf.mmm.security.api.key.symmetric.SecuritySymmetricKey;
import net.sf.mmm.security.api.key.symmetric.SecuritySymmetricKeyConfig;
import net.sf.mmm.security.api.key.symmetric.SecuritySymmetricKeyConfigPbkdf2;
import net.sf.mmm.security.api.key.symmetric.SecuritySymmetricKeyFactory;
import net.sf.mmm.security.api.provider.SecurityProviderConstants;
import net.sf.mmm.security.api.random.SecurityRandomConfigSha1Prng;
import net.sf.mmm.security.api.random.SecurityRandomFactory;
import net.sf.mmm.security.api.sign.SecuritySignature;
import net.sf.mmm.security.api.sign.SecuritySignatureFactory;
import net.sf.mmm.security.api.sign.SecuritySignatureSigner;
import net.sf.mmm.security.api.sign.SecuritySignatureVerifier;
import net.sf.mmm.util.lang.api.BinaryType;

/**
 * Test-case of {@link SecurityBuilder}, {@link SecurityBuilderImpl}, {@link SecurityFactoryBuilder} and more or less
 * this entire security library.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityBuilderTest extends Assertions {

  private static final String TEST_DATA = "Hello world!";

  private static final String HASH_MD5 = "86fb269d190d2c85f6e0468ceca42a20";

  private static final String HASH_SHA1 = "d3486ae9136e7856bc42212385ea797094475802";

  private static final String HASH_SHA256 = "c0535e4be2b79ffd93291305436bf889314e4a3faec05ecffcbb7df31ad9e51a";

  private static final String HASH_DOUBLE_SHA256 = "7982970534e089b839957b7e174725ce1878731ed6d700766e59cb16f1c25e27";

  /**
   * @return the {@link SecurityBuilder} instance to test.
   */
  private SecurityBuilder newBuilder() {

    return new SecurityBuilderImpl();
  }

  /**
   * @return the {@link SecurityFactoryBuilder} instance to test.
   */
  private SecurityFactoryBuilder newFactoryBuilder() {

    return newBuilder().newFactoryBuilder();
  }

  /**
   * Test of {@link SecurityFactoryBuilder#provider()}.
   */
  @Test
  public void testProviderByDefault() {

    // given
    SecurityFactoryBuilder builder = newFactoryBuilder();

    // when
    Provider provider = builder.provider().getProvider();

    // then
    assertThat(provider).isNull();
  }

  /**
   * Test of {@link SecurityFactoryBuilder#provider(String)}.
   */
  @Test
  public void testProviderByName() {

    // given
    BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
    Security.addProvider(bouncyCastleProvider);
    String providerName = bouncyCastleProvider.getName();
    assertThat(providerName).isEqualTo(SecurityProviderConstants.PROVIDER_NAME_BOUNCY_CASTLE);
    SecurityFactoryBuilder builder = newFactoryBuilder();

    // when
    Provider provider = builder.provider(providerName).getProvider();

    // then
    assertThat(provider).isNotNull().isSameAs(Security.getProvider(providerName));
  }

  /**
   * Test of {@link SecurityFactoryBuilder#provider(Provider)}.
   */
  @Test
  public void testProviderByInstance() {

    // given
    Provider bouncyCastleProvider = new BouncyCastleProvider();
    SecurityFactoryBuilder builder = newFactoryBuilder();

    // when
    Provider provider = builder.provider(bouncyCastleProvider).getProvider();

    // then
    assertThat(provider).isNotNull().isSameAs(bouncyCastleProvider);
  }

  /**
   * Test of {@link SecurityFactoryBuilder#hash(net.sf.mmm.security.api.hash.SecurityHashConfig)} with SHA-256.
   */
  @Test
  public void testHashSha256() {

    // given
    SecurityFactoryBuilder builder = newFactoryBuilder();
    SecurityHashConfigSha256 config = SecurityHashConfigSha256.SHA_256;

    // when
    SecurityHashFactory hashFactory = hash(builder, config);

    // then
    assertThat(hashFactory).isNotNull();
    assertThat(hashFactory.getAlgorithm()).isEqualTo(config.getAlgorithm());
    assertThat(hashFactory.toString()).isEqualTo(config.getAlgorithm());
    byte[] data = hashFactory.newHashCreator().process(TEST_DATA.getBytes());
    assertThat(BinaryType.formatHex(data)).isEqualTo(HASH_SHA256);
  }

  /**
   * Test of {@link SecurityFactoryBuilder#hash(SecurityHashConfig)} with double SHA-256.
   */
  @Test
  public void testHash2xSha256() {

    // given
    SecurityFactoryBuilder builder = newFactoryBuilder();

    // when
    SecurityHashFactory hashFactory = hash(builder, new SecurityHashConfigSha256(2));

    // then
    assertThat(hashFactory).isNotNull();
    assertThat(hashFactory.getAlgorithm()).isEqualTo(SecurityAlgorithmSha2.ALGORITHM_SHA_256);
    assertThat(hashFactory.toString()).isEqualTo("SHA-256 (2x)");
    byte[] data = hashFactory.newHashCreator().process(TEST_DATA.getBytes());
    assertThat(BinaryType.formatHex(data)).isEqualTo(HASH_DOUBLE_SHA256);
  }

  /**
   * Test of {@link SecurityFactoryBuilder#hash(SecurityHashConfig)} with MD5.
   */
  @Test
  public void testHashMd5() {

    // given
    SecurityFactoryBuilder builder = newFactoryBuilder();
    SecurityHashConfig config = new SecurityHashConfig("MD5");

    // when
    SecurityHashFactory hashFactory = hash(builder, config);

    // then
    assertThat(hashFactory).isNotNull();
    assertThat(hashFactory.getAlgorithm()).isEqualTo(config.getAlgorithm());
    assertThat(hashFactory.toString()).isEqualTo(config.getAlgorithm());
    byte[] data = hashFactory.newHashCreator().process(TEST_DATA.getBytes());
    assertThat(BinaryType.formatHex(data)).isEqualTo(HASH_MD5);
  }

  /**
   * Test of {@link SecurityFactoryBuilder#hash(SecurityHashConfig)} with MD5.
   */
  @Test
  public void testHashSha1() {

    // given
    SecurityFactoryBuilder builder = newFactoryBuilder();
    SecurityHashConfig config = new SecurityHashConfig("SHA1");

    // when
    SecurityHashFactory hashFactory = hash(builder, config);

    // then
    assertThat(hashFactory).isNotNull();
    assertThat(hashFactory.getAlgorithm()).isEqualTo(config.getAlgorithm());
    assertThat(hashFactory.toString()).isEqualTo(config.getAlgorithm());
    byte[] data = hashFactory.newHashCreator().process(TEST_DATA.getBytes());
    assertThat(BinaryType.formatHex(data)).isEqualTo(HASH_SHA1);
  }

  /**
   * Test of {@link SecurityFactoryBuilder#random(net.sf.mmm.security.api.random.SecurityRandomConfig)} with SHA1PRNG.
   *
   * @throws Exception on error.
   */
  @Test
  public void testRandomSha1Prng() throws Exception {

    // given
    SecurityRandomConfigSha1Prng config = SecurityRandomConfigSha1Prng.SHA1PRNG;
    SecureRandom expectedRandom = SecureRandom.getInstance(config.getAlgorithm());
    SecurityFactoryBuilder builder = newFactoryBuilder();

    // when
    SecurityRandomFactory randomFactory = builder.random(config);

    // then
    verifyRandom(randomFactory, expectedRandom);
  }

  /**
   * Test of {@link SecurityFactoryBuilder#random()} with SHA1PRNG.
   *
   * @throws Exception on error.
   */
  @Test
  public void testRandomByDefault() throws Exception {

    // given
    SecureRandom expectedRandom = SecureRandom.getInstanceStrong();
    SecurityFactoryBuilder builder = newFactoryBuilder();

    // when
    SecurityRandomFactory randomFactory = builder.random();

    // then
    verifyRandom(randomFactory, expectedRandom);
  }

  private void verifyRandom(SecurityRandomFactory randomFactory, SecureRandom expectedRandom) {

    verifyRandom(randomFactory.newSecureRandom(), expectedRandom.getAlgorithm(), expectedRandom.getProvider());
  }

  private void verifyRandom(SecureRandom secureRandom, String algorithm, Provider provider) {

    assertThat(secureRandom.getAlgorithm()).isEqualTo(algorithm);
    if (provider != null) {
      assertThat(secureRandom.getProvider()).isSameAs(provider);
    }
  }

  /**
   * Test of {@link SecurityFactoryBuilder#key(net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyConfig)} with
   * {@link SecurityAsymmetricKeyConfigRsa#RSA_4096}.
   */
  @Test
  public void testKeyRsa() {

    // given
    SecurityFactoryBuilder builder = newFactoryBuilder();

    // when
    builder.random();
    SecurityAsymmetricKeyFactory keyFactory = key(builder, SecurityAsymmetricKeyConfigRsa.RSA_4096);
    SecurityAsymmetricKeyCreator keyCreator = keyFactory.newKeyCreator();
    SecurityAsymmetricKeyPair keyPair = keyCreator.generateKeyPair();

    // then
    verifyKeyPair(keyPair, keyCreator, 550, 2373, 2378);
  }

  /**
   * Test of {@link SecurityFactoryBuilder#key(net.sf.mmm.security.api.key.asymmetric.SecurityAsymmetricKeyConfig)} with
   * {@link SecurityAsymmetricKeyConfigEc#EC_256}.
   */
  @Test
  public void testKeyEc() {

    // given
    SecurityFactoryBuilder builder = newFactoryBuilder();

    // when
    builder.random();
    SecurityAsymmetricKeyFactory keyFactory = key(builder, SecurityAsymmetricKeyConfigEc.EC_256);
    SecurityAsymmetricKeyCreator keyCreator = keyFactory.newKeyCreator();
    SecurityAsymmetricKeyPair keyPair = keyCreator.generateKeyPair();

    // then
    verifyKeyPair(keyPair, keyCreator, 91, 67, 67);
  }

  private void verifyKeyPair(SecurityAsymmetricKeyPair keyPair, SecurityAsymmetricKeyCreator keyCreator, int publicKeyByteCount, int privateKeyByteCountMin,
      int privateKeyByteCountMax) {

    verifyKeyPair(keyPair, publicKeyByteCount, privateKeyByteCountMin, privateKeyByteCountMax);

    SecurityPrivateKey privateKey = keyPair.getPrivateKey();
    SecurityPublicKey publicKey = keyPair.getPublicKey();
    SecurityAsymmetricKeyPair keyPairCopy = keyCreator.deserializeKeyPair(privateKey.getBase64(), publicKey.getBase64());
    assertThat(keyPairCopy).isNotNull();
    assertThat(keyPairCopy.getPrivateKey()).isEqualTo(privateKey);
    assertThat(keyPairCopy.getPublicKey()).isEqualTo(publicKey);
    assertThat(keyPairCopy.getPrivateKey().getKey()).isEqualTo(privateKey.getKey());
    assertThat(keyPairCopy.getPublicKey().getKey()).isEqualTo(publicKey.getKey());

    assertThat(keyCreator.deserializePrivateKey(privateKey.getBase64())).isEqualTo(privateKey);
    assertThat(keyCreator.deserializePublicKey(publicKey.getBase64())).isEqualTo(publicKey);
  }

  private void verifyKeyPair(SecurityAsymmetricKeyPair keyPair, int publicKeyByteCount, int privateKeyByteCountMin, int privateKeyByteCountMax) {

    assertThat(keyPair).isNotNull();

    SecurityPrivateKey privateKey = keyPair.getPrivateKey();
    assertThat(privateKey).isNotNull();
    assertThat(privateKey.getData()).isNotNull();
    assertThat(privateKey.getData().length).isBetween(privateKeyByteCountMin, privateKeyByteCountMax);
    assertThat(privateKey.getKey()).isNotNull();

    SecurityPublicKey publicKey = keyPair.getPublicKey();
    assertThat(publicKey).isNotNull();
    assertThat(publicKey.getData()).isNotNull().hasSize(publicKeyByteCount);
    assertThat(publicKey.getKey()).isNotNull();
  }

  /**
   * Test of {@link SecurityFactoryBuilder#crypt(net.sf.mmm.security.api.crypt.SecurityCryptorConfig)} with
   * {@link SecuritySymmetricCryptorConfigAes#AES_GCM_256}.
   *
   * @throws Exception if something goes wrong.
   */
  @Test
  public void testCryptAesGcm256() throws Exception {

    // given
    SecurityFactoryBuilder builder = newFactoryBuilder();
    String password = "$ecr4t";
    String secretMessage = "Hello World! This is a very secret message.";
    byte[] rawMessage = secretMessage.getBytes("UTF-8");
    SecuritySymmetricCryptorConfigAes configuration = SecuritySymmetricCryptorConfigAes.AES_GCM_256;

    // when
    builder.provider(new BouncyCastleProvider()); // JCA/JCE is buggy here, only works with BC
    builder.random();
    SecuritySymmetricCryptorFactory cryptorFactory = crypt(builder, configuration);
    SecuritySymmetricKeyFactory keyFactory = key(builder, SecuritySymmetricKeyConfigPbkdf2.PBKDF2_WITH_HMAC_SHA256);
    SecuritySymmetricKey key = keyFactory.newKeyCreator().createKey(password);
    SecurityEncryptor encryptor = cryptorFactory.newEncryptor(key);
    byte[] encryptedMessage = encryptor.crypt(rawMessage, true);
    SecurityDecryptor decryptor = cryptorFactory.newDecryptor(key);
    byte[] decryptedMessage = decryptor.crypt(encryptedMessage, true);

    // then
    assertThat(encryptedMessage).isNotEqualTo(rawMessage);
    assertThat(encryptedMessage.length - rawMessage.length).isGreaterThanOrEqualTo(configuration.getNonceSize());
    assertThat(decryptedMessage).isEqualTo(rawMessage);
  }

  @Test
  public void testKeyStoreJceks() throws Exception {

    String password = "$ecr4t";
    File file = File.createTempFile("thankpoint.security", ".jceks");
    file.delete();
    SecurityFileResource resource = new SecurityFileResource(file);
    doTestKeyStore(new SecurityKeyStoreConfigJceks(resource, password), file);
  }

  @Test
  public void testKeyStoreJks() throws Exception {

    String password = "$ecr4t";
    File file = File.createTempFile("thankpoint.security", ".jks");
    file.delete();
    SecurityFileResource resource = new SecurityFileResource(file);
    doTestKeyStore(new SecurityKeyStoreConfigJks(resource, password), file);
  }

  @Test
  public void testKeyStorePkcs12() throws Exception {

    String password = "$ecr4t";
    File file = File.createTempFile("thankpoint.security", ".p12");
    file.delete();
    SecurityFileResource resource = new SecurityFileResource(file);
    doTestKeyStore(new SecurityKeyStoreConfigPkcs12(resource, password), file);
  }

  @Test
  public void testKeyStoreBks() throws Exception {

    BouncyCastleProvider bouncyCastleProvider = new BouncyCastleProvider();
    Security.addProvider(bouncyCastleProvider);
    String password = "$ecr4t";
    File file = File.createTempFile("thankpoint.security", ".p12");
    file.delete();
    SecurityFileResource resource = new SecurityFileResource(file);
    doTestKeyStore(new SecurityKeyStoreConfigBks(resource, password), file);
  }

  private void doTestKeyStore(SecurityKeyStoreConfig configuration, File file) throws IOException {

    // given
    String password = "$4cret";
    SecurityFactoryBuilder builder = newFactoryBuilder();
    SecurityCertificateConfig certConfig = new SecurityCertificateConfigX509();

    // when
    builder.random();
    SecurityAsymmetricKeyFactory keyFactory = key(builder, SecurityAsymmetricKeyConfigRsa.RSA_4096);
    SecurityAsymmetricKeyPair keyPair = keyFactory.newKeyCreator().generateKeyPair();
    SecurityKeyStore keyStore = builder.keyStore(configuration);
    String alias = "alias1";
    SecurityCertificateCreator certificateCreator = builder.cert(certConfig);
    SecurityCertificatePath certificatePath;
    SecurityCertificateDataBean certificateData = new SecurityCertificateDataBean();
    certificateData.setIssuer("CN=thankpoint");
    certificateData.setSubject("CN=admin@thankpoint.github.io");
    certificateData.setNotAfter(Instant.now().plus(Duration.ofDays(365)));
    certificateData.setSignatureAlgorithm("SHA256WithRSA");
    SecurityCertificate certificate = certificateCreator.generateCertificate(keyPair, certificateData);
    keyStore.setKeyPair(alias, keyPair, password, new SecurityCertificatePathGeneric(certificate));
    keyStore.save();
    file.deleteOnExit();

    // then
    assertThat(file).exists().isFile();
    SecurityKeyStore keyStore2 = builder.keyStore(configuration);
    SecurityKeySet keyPair2 = keyStore2.getKeyPair(alias, password);
    assertThat(keyPair2).isEqualTo(keyPair);
    file.delete();
  }

  /**
   * Test of {@link SecurityFactoryBuilder#crypt(net.sf.mmm.security.api.crypt.SecurityCryptorConfig)} with
   * {@link SecurityAsymmetricCryptorConfigRsa#RSA_4096}.
   *
   * @throws Exception if something goes wrong.
   */
  @Test
  public void testCryptRsa4096() throws Exception {

    doTestCryptAsymmetric(SecurityAsymmetricCryptorConfigRsa.RSA_4096);
  }

  private void doTestCryptAsymmetric(SecurityAsymmetricCryptorConfig configuration) throws UnsupportedEncodingException {

    // given
    SecurityFactoryBuilder builder = newFactoryBuilder();
    String secretMessage = "Hello World! This is a very secret message.";
    byte[] rawMessage = secretMessage.getBytes("UTF-8");

    // when
    builder.random();
    SecurityAsymmetricKeyFactory keyFactory = key(builder, configuration.getKeyAlgorithmConfig());
    SecurityAsymmetricKeyPair keyPair = keyFactory.newKeyCreator().generateKeyPair();
    SecurityCryptorFactory cryptorFactory = cryptUnsafe(builder, configuration);
    SecurityEncryptor encryptor;
    SecurityDecryptor decryptor;
    byte[] encryptedMessage = null;
    byte[] decryptedMessage;
    if (configuration.isPrivatePublic()) {
      // when
      encryptor = cryptorFactory.newEncryptorUnsafe(keyPair.getPrivateKey().getKey());
      encryptedMessage = encryptor.crypt(rawMessage, true);
      decryptor = cryptorFactory.newDecryptorUnsafe(keyPair.getPublicKey().getKey());
      decryptedMessage = decryptor.crypt(encryptedMessage, true);

      // then
      assertThat(encryptedMessage).isNotEqualTo(rawMessage);
      assertThat(decryptedMessage).isEqualTo(rawMessage);
    }
    if (configuration.isPublicPrivate()) {
      // when
      encryptor = cryptorFactory.newEncryptorUnsafe(keyPair.getPublicKey().getKey());
      byte[] encryptedMessage2 = encryptor.crypt(rawMessage, true);
      decryptor = cryptorFactory.newDecryptorUnsafe(keyPair.getPrivateKey().getKey());
      decryptedMessage = decryptor.crypt(encryptedMessage2, true);

      // then
      assertThat(encryptedMessage2).isNotEqualTo(rawMessage);
      assertThat(encryptedMessage2).isNotEqualTo(encryptedMessage);
      assertThat(decryptedMessage).isEqualTo(rawMessage);
    }
  }

  /**
   * Test of {@link SecurityFactoryBuilder#crypt(net.sf.mmm.security.api.crypt.SecurityCryptorConfig)} with
   * {@link SecurityAsymmetricCryptorConfigEcies#ECIES_256}.
   *
   * @throws Exception if something goes wrong.
   */
  @Test
  public void testCryptEcies256() throws Exception {

    Security.addProvider(new BouncyCastleProvider());
    doTestCryptAsymmetric(SecurityAsymmetricCryptorConfigEcies.ECIES_256);
  }

  /**
   * Test of {@link SecurityFactoryBuilder#crypt(net.sf.mmm.security.api.crypt.SecurityCryptorConfig)} with
   * {@link SecurityAsymmetricCryptorConfigCurve25519#CURVE_25519}.
   *
   * @throws Exception if something goes wrong.
   */
  @Test
  public void testCryptCurve25519() throws Exception {

    Security.addProvider(new BouncyCastleProvider());
    doTestCryptAsymmetric(SecurityAsymmetricCryptorConfigCurve25519.CURVE_25519);
  }

  /**
   * Test of {@link SecurityFactoryBuilder#signUsingHashAndCryptor()
   *
   * @throws Exception if something goes wrong.
   */
  @Test
  public void testSignUsingHashSha256x2AndCryptorRsa4096() throws Exception {

    // given
    SecurityFactoryBuilder builder = newFactoryBuilder();
    String secretMessage = TEST_DATA;
    byte[] rawMessage = secretMessage.getBytes("UTF-8");
    SecurityAsymmetricCryptorConfigRsa configuration = SecurityAsymmetricCryptorConfigRsa.RSA_4096;

    // when
    builder.random();
    SecurityHashFactory hashFactory = hash(builder, new SecurityHashConfigSha256(2));
    SecurityAsymmetricCryptorFactoryBidirectional cryptorFactory = crypt(builder, configuration);
    SecurityAsymmetricKeyFactory keyFactory = key(builder, configuration.getKeyAlgorithmConfig());
    SecurityAsymmetricKeyPair keyPair = keyFactory.newKeyCreator().generateKeyPair();
    SecuritySignatureFactory signatureFactory = builder.signUsingHashAndCryptor();
    SecurityPrivateKey privateKey = keyPair.getPrivateKey();
    SecuritySignatureSigner signer = signatureFactory.newSigner(privateKey);
    byte[] signature = signer.sign(rawMessage, true);
    SecurityPublicKey publicKey = keyPair.getPublicKey();
    SecuritySignatureVerifier verifier = signatureFactory.newVerifier(publicKey);
    boolean verified = verifier.verify(rawMessage, signature);

    // then
    assertThat(verified).isTrue();
    byte[] hash = hashFactory.newHashCreator().hash(rawMessage, true);
    byte[] crypt = cryptorFactory.newEncryptor(privateKey).crypt(hash, true);
    assertThat(signature).isEqualTo(crypt);
    assertThat(verifier.verify(rawMessage, new SecuritySignature(signature))).isTrue();
  }

  private SecurityCryptorFactory cryptUnsafe(SecurityFactoryBuilder builder, SecurityCryptorConfig<?> config) {

    SecurityCryptorFactory cryptorFactory = builder.cryptUnsafe(config);
    verifyFactory(cryptorFactory, config);
    return cryptorFactory;
  }

  private SecuritySymmetricCryptorFactory crypt(SecurityFactoryBuilder builder, SecuritySymmetricCryptorConfig config) {

    SecuritySymmetricCryptorFactory cryptorFactory = builder.crypt(config);
    verifyFactory(cryptorFactory, config);
    return cryptorFactory;
  }

  private SecurityAsymmetricCryptorFactoryBidirectional crypt(SecurityFactoryBuilder builder, SecurityAsymmetricCryptorConfigBidirectional config) {

    SecurityAsymmetricCryptorFactoryBidirectional cryptorFactory = builder.crypt(config);
    verifyFactory(cryptorFactory, config);
    return cryptorFactory;
  }

  private SecurityAsymmetricCryptorFactoryPrivatePublic crypt(SecurityFactoryBuilder builder, SecurityAsymmetricCryptorConfigPrivatePublic config) {

    SecurityAsymmetricCryptorFactoryPrivatePublic cryptorFactory = builder.crypt(config);
    verifyFactory(cryptorFactory, config);
    return cryptorFactory;
  }

  private SecurityAsymmetricCryptorFactoryPublicPrivate crypt(SecurityFactoryBuilder builder, SecurityAsymmetricCryptorConfigPublicPrivate config) {

    SecurityAsymmetricCryptorFactoryPublicPrivate cryptorFactory = builder.crypt(config);
    verifyFactory(cryptorFactory, config);
    return cryptorFactory;
  }

  private SecurityAsymmetricKeyFactory key(SecurityFactoryBuilder builder, SecurityAsymmetricKeyConfig config) {

    SecurityAsymmetricKeyFactory keyFactory = builder.key(config);
    verifyFactory(keyFactory, config);
    return keyFactory;
  }

  private SecuritySymmetricKeyFactory key(SecurityFactoryBuilder builder, SecuritySymmetricKeyConfig config) {

    SecuritySymmetricKeyFactory keyFactory = builder.key(config);
    verifyFactory(keyFactory, config);
    return keyFactory;
  }

  private SecurityHashFactory hash(SecurityFactoryBuilder builder, SecurityHashConfig config) {

    SecurityHashFactory hashFactory = builder.hash(config);
    String toString = config.getAlgorithm();
    int iterationCount = config.getIterationCount();
    if (iterationCount > 1) {
      toString = toString + " (" + iterationCount + "x)";
    }
    verifyFactory(hashFactory, config, toString);
    return hashFactory;
  }

  private void verifyFactory(AbstractSecurityFactory factory, SecurityAlgorithmConfig config) {

    verifyFactory(factory, config, config.getAlgorithm());
  }

  private void verifyFactory(AbstractSecurityFactory factory, SecurityAlgorithmConfig config, String toString) {

    assertThat(factory.getAlgorithm()).isEqualTo(config.getAlgorithm());
    assertThat(factory.toString()).isEqualTo(toString);
    assertThat(config.toString()).isEqualTo(config.getAlgorithm());
  }

}
