package de.georgg

import org.assertj.core.api.Assertions.assertThat
import org.junit.Test

class ExtensionsTest {
  
  @Test
  fun `Load key store from file`() {
    val keyStore = defaultKeyStore().resource("classpath:alice_keystore.p12")
    
    assertThat(keyStore).isNotNull
  }
  
  @Test
  fun `Load private key from password protected key store`() {
    val keyStore = defaultKeyStore().resource("classpath:alice_keystore.p12")
    val (privateKey, certificate) = keyStore.privateKey("alice", "alice12345")
    
    assertThat(privateKey).isNotNull
    assertThat(certificate).isNotNull
  }
}