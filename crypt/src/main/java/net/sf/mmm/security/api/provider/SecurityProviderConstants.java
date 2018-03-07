package net.sf.mmm.security.api.provider;

/**
 * Constants for {@link SecurityProviderBuilder} and related APIs.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityProviderConstants {

  /**
   * The {@link java.security.Provider#getName() provider name} of
   * {@link org.bouncycastle.jce.provider.BouncyCastleProvider} (third party, requires extra dependency such as
   * {@code org.bouncycastle:bcprov-jdk15on}). Has to be
   * {@link java.security.Security#addProvider(java.security.Provider) installed} manually before using.
   */
  String PROVIDER_NAME_BOUNCY_CASTLE = "BC";

  /**
   * The {@link java.security.Provider#getName() provider name} of the main default provider that comes with the JVM.
   */
  String PROVIDER_NAME_SUN = "SUN";

}
