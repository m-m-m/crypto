package io.github.mmm.crypto;

import io.github.mmm.crypto.algorithm.CryptoAlgorithm;

/// The abstract interface for any object that is based on a security [algorithm][#getAlgorithm()].
///
/// @since 1.0.0
public abstract interface CryptoProcessor extends CryptoAlgorithm {

  /// Generic method to process and transform data.
  /// <table summary="method usage examples" border="1">
  /// <tr>
  /// <th>[CryptoProcessor]</th>
  /// <th>Equivalent of [process][#process(byte\[\])](input)</th>
  /// </tr>
  /// <tr>
  /// <td>[io.github.mmm.crypto.hash.HashCreator]</td>
  /// <td>`[update][io.github.mmm.crypto.hash.HashCreator#update(byte[])](input); return
  /// [hash][io.github.mmm.crypto.hash.HashCreator#hash(boolean)](true);`</td>
  /// </tr>
  /// <tr>
  /// <td>[io.github.mmm.crypto.crypt.Cryptor]</td>
  /// <td>`return [crypt][io.github.mmm.crypto.crypt.Cryptor#crypt(byte[], boolean)](input, true);`</td>
  /// </tr>
  /// <tr>
  /// <td>[io.github.mmm.crypto.asymmetric.sign.SignatureSigner]</td>
  /// <td>`[update][io.github.mmm.crypto.asymmetric.sign.SignatureSigner#update(byte[])](input); return
  /// [signAfterUpdateRaw][io.github.mmm.crypto.asymmetric.sign.SignatureSigner#signAfterUpdateRaw(boolean)](true);`</td>
  /// </tr>
  /// <tr>
  /// <td>[io.github.mmm.crypto.asymmetric.sign.SignatureVerifier]</td>
  /// <td>`throw new [UnsupportedOperationException]();`</td>
  /// </tr>
  /// </table>
  ///
  /// @param input the data to process.
  /// @return the transformed `input` data.
  default byte[] process(byte[] input) {

    return process(input, 0, input.length);
  }

  /// Generic method to process and transform data.
  /// <table summary="method usage examples" border="1">
  /// <tr>
  /// <th>[CryptoProcessor]</th>
  /// <th>Equivalent of [process][#process(byte\[\], int, int)](input, offset, length)</th>
  /// </tr>
  /// <tr>
  /// <td>[io.github.mmm.crypto.hash.HashCreator]</td>
  /// <td>`[update][io.github.mmm.crypto.hash.HashCreator#update(byte[], int, int)](input, offset, length); return
  /// [hash][io.github.mmm.crypto.hash.HashCreator#hash(boolean)](true);`</td>
  /// </tr>
  /// <tr>
  /// <td>[io.github.mmm.crypto.crypt.Cryptor]</td>
  /// <td>`return [crypt][io.github.mmm.crypto.crypt.Cryptor#crypt(byte[], int, int, boolean)](input, offset, length,
  /// true);`</td>
  /// </tr>
  /// <tr>
  /// <td>[io.github.mmm.crypto.asymmetric.sign.SignatureSigner]</td>
  /// <td>`[update][io.github.mmm.crypto.asymmetric.sign.SignatureSigner#update(byte[], int, int)](input, offset,
  /// length); return
  /// [signAfterUpdate][io.github.mmm.crypto.asymmetric.sign.SignatureSigner#signAfterUpdate(boolean)](true);`</td>
  /// </tr>
  /// <tr>
  /// <td>[io.github.mmm.crypto.asymmetric.sign.SignatureVerifier]</td>
  /// <td>`throw new [UnsupportedOperationException]();`</td>
  /// </tr>
  /// </table>
  ///
  /// @param input the data to process.
  /// @param offset the index where to start reading data from `input`.
  /// @param length the number of bytes to read from `input`.
  /// @return the transformed `input` data.
  default byte[] process(byte[] input, int offset, int length) {

    return process(input, offset, length, true);
  }

  /// Generic method to process and transform data.
  /// <table summary="method usage examples" border="1">
  /// <tr>
  /// <th>[CryptoProcessor]</th>
  /// <th>Equivalent of [process][#process(byte\[\], int, int, boolean)](input, offset, length, complete)</th>
  /// </tr>
  /// <tr>
  /// <td>[io.github.mmm.crypto.hash.HashCreator]</td>
  /// <td>`[update][io.github.mmm.crypto.hash.HashCreator#update(byte[], int, int)](input, offset, length); return
  /// [hash][io.github.mmm.crypto.hash.HashCreator#hash(boolean)](complete);`</td>
  /// </tr>
  /// <tr>
  /// <td>[io.github.mmm.crypto.crypt.Cryptor]</td>
  /// <td>`return [crypt][io.github.mmm.crypto.crypt.Cryptor#crypt(byte[], int, int, boolean)](input, offset, length,
  /// true);`</td>
  /// </tr>
  /// <tr>
  /// <td>[io.github.mmm.crypto.asymmetric.sign.SignatureSigner]</td>
  /// <td>`[update][io.github.mmm.crypto.asymmetric.sign.SignatureSigner#update(byte[], int, int)](input, offset,
  /// length); return
  /// [signAfterUpdate][io.github.mmm.crypto.asymmetric.sign.SignatureSigner#signAfterUpdate(boolean)](complete);`</td>
  /// </tr>
  /// <tr>
  /// <td>[io.github.mmm.crypto.asymmetric.sign.SignatureVerifier]</td>
  /// <td>`throw new [UnsupportedOperationException]();`</td>
  /// </tr>
  /// </table>
  ///
  /// @param input the data to process.
  /// @param offset the index where to start reading data from `input`.
  /// @param length the number of bytes to read from `input`.
  /// @param complete - `true` to complete/reset this processor after processing the given `input`, `false` otherwise.
  /// @return the transformed `input` data.
  default byte[] process(byte[] input, int offset, int length, boolean complete) {

    throw new UnsupportedOperationException();
  }

  /// @param input the [CryptoBinary] [containing the data][CryptoBinary#getData()] to process.
  /// @param complete - `true` to complete/reset this processor after processing the given `input`, `false` otherwise.
  /// @return the transformed `input` data.
  /// @see #process(byte[])
  default byte[] process(CryptoBinary input, boolean complete) {

    byte[] data = input.getRawData();
    return process(data, 0, data.length, complete);
  }

  /// Will reset the internal state of this object. Please note that complex algorithms especially for
  /// [io.github.mmm.crypto.crypt.Cryptor] may **not** reusable. It is therefore preferable to always create a fresh
  /// instance for each cryptographic task.
  ///
  /// @see java.security.MessageDigest#reset()
  void reset();

}
