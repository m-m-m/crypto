package io.github.mmm.crypto.asymmetric.sign;

import io.github.mmm.crypto.CryptoChunker;
import io.github.mmm.crypto.hash.HashCreator;

/**
 * The abstract interface for an signing or verification function of an asymmetric
 * {@link io.github.mmm.crypto.crypt.Cryptor cryptographic algorithm} typically in combination with a
 * {@link HashCreator hasing algorithm}. It is similar to {@link java.security.Signature} but gives additional
 * abstraction and flexibility.
 *
 * @see SignatureSigner
 * @see SignatureVerifier
 * @see SignatureProcessorFactory
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract interface SignatureProcessor extends CryptoChunker {

}
