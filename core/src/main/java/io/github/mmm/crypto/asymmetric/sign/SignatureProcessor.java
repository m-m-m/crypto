package io.github.mmm.crypto.asymmetric.sign;

import io.github.mmm.crypto.CryptoChunker;
import io.github.mmm.crypto.hash.HashCreator;

/// The abstract interface for an signing or verification function of an asymmetric
/// [cryptographic algorithm][io.github.mmm.crypto.crypt.Cryptor] typically in combination with a
/// [hasing algorithm][HashCreator]. It is similar to [java.security.Signature] but gives additional
/// abstraction and flexibility.
///
/// @see SignatureSigner
/// @see SignatureVerifier
/// @see SignatureProcessorFactory
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public abstract interface SignatureProcessor extends CryptoChunker {

}
