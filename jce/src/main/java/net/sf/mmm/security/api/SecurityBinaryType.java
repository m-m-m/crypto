/* Copyright (c) The m-m-m Team, Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0 */
package net.sf.mmm.security.api;

import net.sf.mmm.binary.api.BinaryType;

/**
 * {@link BinaryType} for security content such as {@link net.sf.mmm.security.api.hash.SecurityHash},
 * {@link net.sf.mmm.security.api.asymmetric.sign.SecuritySignature}, encrypted data, serialized {@link java.security.Key}s, etc.
 */
public class SecurityBinaryType extends BinaryType {

  /**
   * The constructor.
   *
   * @param data the raw binary {@link #getData() data}.
   */
  public SecurityBinaryType(byte[] data) {

    super(data);
  }

  byte[] getRawData() {

    return this.data;
  }

}
