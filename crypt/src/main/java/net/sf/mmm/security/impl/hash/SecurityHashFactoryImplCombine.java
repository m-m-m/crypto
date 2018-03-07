package net.sf.mmm.security.impl.hash;

import net.sf.mmm.security.api.hash.SecurityHashCreator;
import net.sf.mmm.security.api.hash.SecurityHashFactory;
import net.sf.mmm.security.impl.AbstractSecurityAlgorithm;

/**
 * The implementation of {@link SecurityHashFactory} that combines multiple {@link SecurityHashFactory} instances by
 * sequentially applying the hashes.
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public class SecurityHashFactoryImplCombine extends AbstractSecurityAlgorithm implements SecurityHashFactory {

  private final SecurityHashFactory[] factories;

  /**
   * The constructor.
   *
   * @param factories the {@link SecurityHashFactory} instances to combine.
   */
  public SecurityHashFactoryImplCombine(SecurityHashFactory[] factories) {
    super();
    this.factories = factories;
  }

  @Override
  public String getAlgorithm() {

    return getAlgorithm(this.factories);
  }

  @Override
  public SecurityHashCreator newHashCreator() {

    SecurityHashCreator[] generators = new SecurityHashCreator[this.factories.length];
    for (int i = 0; i < this.factories.length; i++) {
      generators[i] = this.factories[i].newHashCreator();
    }
    return new SecurityHashCreatorImplCombine(generators);
  }

}
