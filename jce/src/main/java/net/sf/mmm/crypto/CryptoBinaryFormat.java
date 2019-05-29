package net.sf.mmm.crypto;

/**
 * Interface for the concept and constants of different formats of a {@link CryptBinary binary representation}. The
 * formats {@link #FORMAT_ENCODED} and {@link #FORMAT_COMPACT} shall always be accepted. For generic implementations
 * that only support a single format both formats can be used synonymously. Specific implementations may also support
 * additional supports such as e.g. {@link net.sf.mmm.crypto.asymmetric.key.ec.AsymmetricKeyPairEc#FORMAT_UNCOMORESSED}.
 *
 * @see net.sf.mmm.crypto.asymmetric.key.AsymmetricKeyCreator#createPrivateKey(byte[], String)
 * @see net.sf.mmm.crypto.asymmetric.key.AsymmetricKeyCreator#createPublicKey(byte[])
 * @see net.sf.mmm.crypto.asymmetric.key.AsymmetricKeyCreator#createKeyPair(byte[], String)
 * @see net.sf.mmm.crypto.asymmetric.key.AsymmetricKeyCreator#asData(java.security.PrivateKey, String)
 * @see net.sf.mmm.crypto.asymmetric.key.AsymmetricKeyCreator#asData(java.security.PublicKey, String)
 * @see net.sf.mmm.crypto.asymmetric.key.AsymmetricKeyCreator#asData(net.sf.mmm.crypto.asymmetric.key.AsymmetricKeyPair,
 *      String)
 *
 * @since 1.0.0
 */
public interface CryptoBinaryFormat {

  /**
   * The format for the encoded binary representation. This is the most universal, portable and standardized format.
   * However, it is also a large representation according to the {@link CryptBinary#getLength() length}. If you want to
   * store the {@link CryptBinary#getData() raw data} in the most efficient way use {@link #FORMAT_COMPACT} instead.
   *
   * @see java.security.Key#getEncoded()
   */
  String FORMAT_ENCODED = "Encoded";

  /**
   * The format for compact binary representation. This is the smallest representation that is supported.
   */
  String FORMAT_COMPACT = "Compact";

}
