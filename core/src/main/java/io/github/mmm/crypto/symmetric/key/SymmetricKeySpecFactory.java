package io.github.mmm.crypto.symmetric.key;

import java.security.spec.KeySpec;

/**
 * Interface for a factory used to {@link #createKeySpec(String) create} {@link KeySpec}s for a given password.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SymmetricKeySpecFactory {

  /**
   * @param password the secret password.
   * @return the {@link KeySpec} for the given password. May contain additional information like salt.
   */
  KeySpec createKeySpec(String password);

}
