package net.sf.mmm.security.api;

/**
 * Interface for the concept and constants of different formats of a {@link SecurityBinaryType binary representation}.
 * The formats {@link #FORMAT_ENCODED} and {@link #FORMAT_COMPACT} shall always be accepted. For generic implementations
 * that only support a single format both formats can be used synonymously. Specific implementations may also support
 * additional supports such as e.g.
 * {@link net.sf.mmm.security.api.asymmetric.key.ec.SecurityAsymmetricKeyPairEc#FORMAT_UNCOMORESSED}.
 *
 * @see net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyCreator#createPrivateKey(byte[], String)
 * @see net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyCreator#createPublicKey(byte[])
 * @see net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyCreator#createKeyPair(byte[], String)
 * @see net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyCreator#asData(java.security.PrivateKey, String)
 * @see net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyCreator#asData(java.security.PublicKey, String)
 * @see net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyCreator#asData(net.sf.mmm.security.api.asymmetric.key.SecurityAsymmetricKeyPair,
 *      String)
 *
 * @since 1.0.0
 */
public interface SecurityBinaryFormat {

  /**
   * The format for the encoded binary representation. This is the most universal, portable and standardized format.
   * However, it is also a large representation according to the {@link SecurityBinaryType#getLength() length}. If you
   * want to store the {@link SecurityBinaryType#getData() raw data} in the most efficient way use
   * {@link #FORMAT_COMPACT} instead.
   *
   * @see java.security.Key#getEncoded()
   */
  String FORMAT_ENCODED = "Encoded";

  /**
   * The format for compact binary representation. This is the smallest representation that is supported.
   */
  String FORMAT_COMPACT = "Compact";

}
