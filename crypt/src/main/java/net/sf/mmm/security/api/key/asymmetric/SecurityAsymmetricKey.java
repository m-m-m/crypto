package net.sf.mmm.security.api.key.asymmetric;

import java.security.Key;

import net.sf.mmm.security.api.key.SecurityKey;

/**
 * Interface for a {@link SecurityKey} representing an {@link SecurityAsymmetricKeyPair asymmetric key}.
 *
 * @param <K> the type of the wrapped {@link #getKey()}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityAsymmetricKey<K extends Key> extends SecurityKey<K> {

}
