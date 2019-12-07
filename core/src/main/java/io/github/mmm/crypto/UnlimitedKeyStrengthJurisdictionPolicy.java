package io.github.mmm.crypto;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.security.NoSuchAlgorithmException;
import java.security.Permission;
import java.security.PermissionCollection;
import java.util.Map;

import javax.crypto.Cipher;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Code from <a href=
 * "https://stackoverflow.com/questions/1179672/how-to-avoid-installing-unlimited-strength-jce-policy-files-when-deploying-an">Stackoverflow:
 * how to avoid installing unlimited strength jce policy files</a>.
 *
 * @author ntoskrnl, Vadzim
 * @since 1.0.0
 */
public class UnlimitedKeyStrengthJurisdictionPolicy {

  private static final Logger LOG = LoggerFactory.getLogger(UnlimitedKeyStrengthJurisdictionPolicy.class);

  private static boolean isRestrictedCryptography() throws NoSuchAlgorithmException {

    return Cipher.getMaxAllowedKeyLength("AES/ECB/NoPadding") <= 128;
  }

  private static void removeCryptographyRestrictions() {

    try {
      if (!isRestrictedCryptography()) {
        LOG.trace("Cryptography restrictions removal not needed");
        return;
      }
      /*
       * Do the following, but with reflection to bypass access checks:
       *
       * JceSecurity.isRestricted = false; JceSecurity.defaultPolicy.perms.clear();
       * JceSecurity.defaultPolicy.add(CryptoAllPermission.INSTANCE);
       */
      Class<?> jceSecurity = Class.forName("javax.crypto.JceSecurity");
      Class<?> cryptoPermissions = Class.forName("javax.crypto.CryptoPermissions");
      Class<?> cryptoAllPermission = Class.forName("javax.crypto.CryptoAllPermission");

      Field isRestrictedField = jceSecurity.getDeclaredField("isRestricted");
      isRestrictedField.setAccessible(true);
      Field modifiersField = Field.class.getDeclaredField("modifiers");
      modifiersField.setAccessible(true);
      modifiersField.setInt(isRestrictedField, isRestrictedField.getModifiers() & ~Modifier.FINAL);
      isRestrictedField.set(null, Boolean.FALSE);

      Field defaultPolicyField = jceSecurity.getDeclaredField("defaultPolicy");
      defaultPolicyField.setAccessible(true);
      PermissionCollection defaultPolicy = (PermissionCollection) defaultPolicyField.get(null);

      Field perms = cryptoPermissions.getDeclaredField("perms");
      perms.setAccessible(true);
      ((Map<?, ?>) perms.get(defaultPolicy)).clear();

      Field instance = cryptoAllPermission.getDeclaredField("INSTANCE");
      instance.setAccessible(true);
      defaultPolicy.add((Permission) instance.get(null));

      LOG.info("Successfully removed cryptography restrictions");
    } catch (Exception e) {
      LOG.warn("Failed to remove cryptography restrictions", e);
    }
  }

  static {
    removeCryptographyRestrictions();
  }

  /**
   * Ensures that the class gets loaded and the installation was triggered.
   */
  public static void ensure() {
    // just force loading of this class
  }
}
