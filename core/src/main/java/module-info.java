/*
 * Copyright (c) The m-m-m Team, Licensed under the Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
/**
 * Provides fundamental APIs and helper classes.
 */
module io.github.mmm.crypto {

  requires transitive io.github.mmm.binary;

  requires transitive org.slf4j;

  exports io.github.mmm.crypto;

  exports io.github.mmm.crypto.algorithm;

  exports io.github.mmm.crypto.asymmetric.access;

  exports io.github.mmm.crypto.asymmetric.access.ec.jce;

  exports io.github.mmm.crypto.asymmetric.access.rsa;

  exports io.github.mmm.crypto.asymmetric.cert;

  exports io.github.mmm.crypto.asymmetric.cert.access;

  exports io.github.mmm.crypto.asymmetric.crypt;

  exports io.github.mmm.crypto.asymmetric.crypt.ec;

  exports io.github.mmm.crypto.asymmetric.crypt.rsa;

  exports io.github.mmm.crypto.asymmetric.key;

  exports io.github.mmm.crypto.asymmetric.key.ec;

  exports io.github.mmm.crypto.asymmetric.key.ec.jce;

  exports io.github.mmm.crypto.asymmetric.key.generic;

  exports io.github.mmm.crypto.asymmetric.key.rsa;

  exports io.github.mmm.crypto.asymmetric.sign;

  exports io.github.mmm.crypto.asymmetric.sign.ec;

  exports io.github.mmm.crypto.asymmetric.sign.generic;

  exports io.github.mmm.crypto.asymmetric.sign.rsa;

  exports io.github.mmm.crypto.crypt;

  exports io.github.mmm.crypto.hash;

  exports io.github.mmm.crypto.hash.access;

  exports io.github.mmm.crypto.hash.md5;

  exports io.github.mmm.crypto.hash.sha1;

  exports io.github.mmm.crypto.hash.sha2;

  exports io.github.mmm.crypto.io;

  exports io.github.mmm.crypto.key;

  exports io.github.mmm.crypto.key.store;

  exports io.github.mmm.crypto.key.store.access;

  exports io.github.mmm.crypto.provider;

  exports io.github.mmm.crypto.random;

  exports io.github.mmm.crypto.symmetric.access;

  exports io.github.mmm.crypto.symmetric.access.pbe;

  exports io.github.mmm.crypto.symmetric.crypt;

  exports io.github.mmm.crypto.symmetric.crypt.aes;

  exports io.github.mmm.crypto.symmetric.key;

  exports io.github.mmm.crypto.symmetric.key.pbe;

  exports io.github.mmm.crypto.symmetric.key.spec;

}
