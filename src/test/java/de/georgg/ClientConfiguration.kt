package de.georgg

import org.apache.http.impl.client.HttpClients
import org.apache.http.ssl.SSLContextBuilder
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory
import org.springframework.web.client.RestTemplate
import java.security.KeyStore

@Configuration
open class ClientConfiguration {
  
  private val ca = CertificateAuthority()
  
  companion object {
    fun sslRestTemplate(keyStore: KeyStore, trustStore: KeyStore, passwd: String? = null) : RestTemplate {
      val sslContext = SSLContextBuilder
              .create()
              .loadKeyMaterial(keyStore, passwordOrDefault(passwd))
              .loadTrustMaterial(trustStore, null)
              .build()
      val httpClient = HttpClients
              .custom()
              .setSSLContext(sslContext)
              .build()
      return RestTemplate(HttpComponentsClientHttpRequestFactory(httpClient))
    }
  }
  
  // Alice has her certificate signed by the CA
  @Bean
  open fun alice() = sslRestTemplate(
          defaultKeyStore().resource("classpath:alice_keystore.p12"),
          defaultKeyStore().resource("classpath:alice_truststore.jks"))
 
  // Bob has a self signed certificate
  @Bean
  open fun selfSigned(): RestTemplate {
    val keyPair       = ca.keyPair()
    val principal     = ca.principal("Bob")
    val certificate   = ca.selfSign(keyPair, principal)
    val caCertificate = defaultKeyStore().resource("classpath:ca_truststore.jks").getCertificate("CA")
    
    val keyStore = defaultKeyStore().empty().put("BOB", privateKey = keyPair.private, certificate = certificate)
    val trustStore = defaultKeyStore().empty().put("BOB", certificate).put("CA", caCertificate)
    
    return sslRestTemplate(keyStore, trustStore)
  }
}