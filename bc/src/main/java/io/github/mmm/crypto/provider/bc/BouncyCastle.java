/* Copyright (c) The m-m-m Team, Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0 */
package io.github.mmm.crypto.provider.bc;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.github.mmm.crypto.provider.SecurityProvider;

/// Installer that ensures [BouncyCastleProvider] is [registered][Security#addProvider(java.security.Provider)] to java [Security] on [#install()].
///
/// @author Joerg Hohwiller (hohwille at users.sourceforge.net)
/// @since 1.0.0
public class BouncyCastle {

  private static final Logger LOG = LoggerFactory.getLogger(BouncyCastle.class);

  private static boolean installed = false;

  private static final BouncyCastleProvider PROVIDER = new BouncyCastleProvider();

  private static final SecurityProvider SECURITY_PROVIDER = SecurityProvider.of(PROVIDER);

  /// ensures [BouncyCastleProvider] is [registered][Security#addProvider(java.security.Provider)] to java
  /// [Security].
  public static void install() {

    if (!installed) {
      if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
        Security.addProvider(PROVIDER);
        LOG.debug("Successfully installed bouncy castle provider to java security.");
      }
    }
  }

  /// @return the [BouncyCastleProvider] instance.
  public static BouncyCastleProvider getProvider() {

    return PROVIDER;
  }

  /// @return the [SecurityProvider] for [bouncy castle provider][#getProvider()].
  public static SecurityProvider getSecurityProvider() {

    return SECURITY_PROVIDER;
  }

}
