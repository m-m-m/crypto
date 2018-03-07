package net.sf.mmm.security.api.key.symmetric;

import javax.crypto.SecretKey;

import net.sf.mmm.security.api.key.SecurityKey;
import net.sf.mmm.security.api.key.SecurityKeySet;

/**
 * Interface for a {@link SecurityKey} representing a {@link SecretKey}. This key is used both for encryption as well as
 * decryption and has to be kept secret.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecuritySymmetricKey extends SecurityKey<SecretKey>, SecurityKeySet {

}
