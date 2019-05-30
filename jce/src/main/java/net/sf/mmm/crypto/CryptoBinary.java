/* Copyright (c) The m-m-m Team, Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0 */
package net.sf.mmm.crypto;

import net.sf.mmm.binary.api.BinaryType;

/**
 * {@link BinaryType} for security content such as {@link net.sf.mmm.crypto.hash.Hash},
 * {@link net.sf.mmm.crypto.asymmetric.sign.SignatureBinary}, encrypted data, serialized {@link java.security.Key}s, etc.
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
