package net.sf.mmm.security.api.symmetric.key;

import net.sf.mmm.security.api.AbstractSecurityFactory;
import net.sf.mmm.security.api.key.SecurityKeyFactory;

/**
 * Interface for a {@link AbstractSecurityFactory factory} to {@link #newKeyCreator() create} instances of
 * {@link SecuritySymmetricKeyCreator} for symmetric cryptographic keys.<br>
 * An instance of {@link SecuritySymmetricKeyFactory} therefore represents a configuration with specific
 * {@link java.security.Key} {@link java.security.Key#getAlgorithm() algorithm} and {@link java.security.Key#getFormat()
 * format}(s).
 *
 * @param <C> type of {@link SecuritySymmetricKeyCreator}.
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public interface SecuritySymmetricKeyFactory<C extends SecuritySymmetricKeyCreator<?>> extends SecurityKeyFactory {

  @Override
  C newKeyCreator();

}
