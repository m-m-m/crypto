package net.sf.mmm.security.api.asymmetric.key;

import net.sf.mmm.security.api.AbstractSecurityFactory;
import net.sf.mmm.security.api.key.SecurityKeyCreator;
import net.sf.mmm.security.api.key.SecurityKeyFactory;

/**
 * Interface for a {@link AbstractSecurityFactory factory} to {@link #newKeyCreator() create} instances of
 * {@link SecurityKeyCreator} for asymmetric cryptographic keys.<br>
 * An instance of {@link SecurityAsymmetricKeyFactory} therefore represents a configuration with specific
 * {@link java.security.Key} {@link java.security.Key#getAlgorithm() algorithm} and {@link java.security.Key#getFormat()
 * format}(s).
 *
 * @param <K> type of {@link SecurityAsymmetricKeyCreator}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecurityAsymmetricKeyFactory<K extends SecurityAsymmetricKeyCreator<?, ?, ?>> extends SecurityKeyFactory {

  @Override
  K newKeyCreator();

}
