/* Copyright (c) The m-m-m Team, Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0 */
package io.github.mmm.crypto;

import io.github.mmm.binary.BinaryType;

/**
 * {@link BinaryType} for security content such as {@link io.github.mmm.crypto.hash.Hash},
 * {@link io.github.mmm.crypto.asymmetric.sign.SignatureBinary}, encrypted data, serialized {@link java.security.Key}s,
 * etc.
 */
public class CryptoBinary extends BinaryType {

  /**
   * The constructor.
   *
   * @param data the raw binary {@link #getData() data}.
   */
  public CryptoBinary(byte[] data) {

    super(data);
  }

  byte[] getRawData() {

    return this.data;
  }

}
