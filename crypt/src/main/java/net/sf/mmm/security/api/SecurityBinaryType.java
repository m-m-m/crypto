/* Copyright (c) The m-m-m Team, Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0 */
package net.sf.mmm.security.api;

import net.sf.mmm.util.lang.api.BinaryType;

/**
 * {@link BinaryType} for security content such as {@link net.sf.mmm.security.api.hash.SecurityHash},
 * {@link net.sf.mmm.security.api.sign.SecuritySignature}, or {@link net.sf.mmm.security.api.key.SecurityKey}.
 */
public abstract class SecurityBinaryType extends BinaryType {

  /**
   * The constructor.
   *
   * @param data the raw binary {@link #getData() data}.
   */
  public SecurityBinaryType(byte[] data) {

    super(data);
  }

  /**
   * The constructor.
   *
   * @param base64 the {@link #getData() data} as {@link #getBase64() base64}.
   */
  public SecurityBinaryType(String base64) {

    super(base64);
  }

  byte[] getRawData() {

    return this.data;
  }

}
