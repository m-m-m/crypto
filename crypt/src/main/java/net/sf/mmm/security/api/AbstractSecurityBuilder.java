package net.sf.mmm.security.api;

import java.util.ServiceLoader;

import javax.annotation.PostConstruct;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class ...
 *
 * @author Joerg Hohwiller (hohwille at users.sourceforge.net)
 * @since 1.0.0
 */
public abstract class AbstractSecurityBuilder implements SecurityBuilder {

  private static final Logger LOG = LoggerFactory.getLogger(AbstractSecurityBuilder.class);

  private static SecurityBuilder instance;

  /**
   * The constructor.
   */
  public AbstractSecurityBuilder() {
    super();
  }

  /**
   * @return the priority of this implementation. In case multiple implementations are available the one with the
   *         highest priority will win.
   */
  protected int getPriority() {

    return 0;
  }

  /**
   * Initializes this class for usage from IoC/DI frameworks such as spring. Will register the instance to retrieve it
   * via {@link #getInstance()}. Shall not be called from constructor.
   */
  @PostConstruct
  protected void init() {

    if (instance == null) {
      instance = this;
    } else {
      LOG.warn(
          "SecurityBuilder already available as {} - duplicated instance {} will not be accessible via AbstractSecurityBuilder.getInstance()!",
          instance, this);
    }
  }

  /**
   * @return the instance of {@link SecurityBuilder}.
   */
  public static SecurityBuilder getInstance() {

    if (instance == null) {
      synchronized (AbstractSecurityBuilder.class) {
        if (instance == null) {
          SecurityBuilder builder = createInstance();
          instance = builder;
        }
      }
    }
    if (instance == null) {
      throw new IllegalStateException("No implementation of SecurityBuilder could be found!");
    }
    return instance;
  }

  private static SecurityBuilder createInstance() {

    SecurityBuilder builder = null;
    ServiceLoader<SecurityBuilder> builders = ServiceLoader.load(SecurityBuilder.class);
    int priority = -1;
    for (SecurityBuilder securityBuilder : builders) {
      int currentPriority;
      if (securityBuilder instanceof AbstractSecurityBuilder) {
        currentPriority = ((AbstractSecurityBuilder) securityBuilder).getPriority();
      } else {
        currentPriority = 1;
      }
      if (currentPriority > priority) {
        builder = securityBuilder;
      }
    }
    return builder;
  }

}
