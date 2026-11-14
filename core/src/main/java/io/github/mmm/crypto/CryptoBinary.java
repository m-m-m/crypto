/* Copyright (c) The m-m-m Team, Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0 */
package io.github.mmm.crypto;

import io.github.mmm.binary.BinaryType;

/// [BinaryType] for security content such as [io.github.mmm.crypto.hash.Hash],
/// [io.github.mmm.crypto.asymmetric.sign.SignatureBinary], encrypted data, serialized [java.security.Key]s,
/// etc.
public class CryptoBinary extends BinaryType {

  /// The constructor.
  ///
  /// @param data the raw binary [data][#getData()].
  public CryptoBinary(byte[] data) {

    super(data);
  }

  byte[] getRawData() {

    return this.data;
  }

}
