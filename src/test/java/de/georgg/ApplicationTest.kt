package de.georgg

import org.assertj.core.api.Assertions.assertThat
import org.junit.Ignore
import org.junit.Test
import org.junit.runner.RunWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.web.server.LocalServerPort
import org.springframework.http.*
import org.springframework.test.context.junit4.SpringRunner
import org.springframework.web.client.HttpClientErrorException
import org.springframework.web.client.ResourceAccessException
import org.springframework.web.client.RestTemplate
import java.security.cert.X509Certificate

@RunWith(SpringRunner::class)
@SpringBootTest(
        classes = [Application::class], 
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ApplicationTest {
  
  @LocalServerPort
  var port: Int = 0
  
  @Autowired
  private lateinit var alice: RestTemplate

  @Autowired
  private lateinit var selfSigned: RestTemplate
  
  @Autowired
  private lateinit var ca: CertificateAuthority
  
  @Test
  fun `Alice uses her client certificate to authenticate herself successfully`() {
    val greeting = alice.getForObject("https://localhost:$port/greeting?name=Alice", Greeting::class.java)
    
    assertThat(greeting?.content).isEqualTo("Hello, Alice")
  }
  
  @Test(expected = ResourceAccessException::class)
  fun `Cannot authenticate with self signed client certificate`() {
    selfSigned.getForEntity("https://localhost:$port/greeting", Greeting::class.java)
  }
  
  @Test(expected = HttpClientErrorException::class)
  fun `Alice fails to authenticate herself without credentials`() {   
    val response = alice.getForList<Certificate>("https://localhost:$port/certificates/list", HttpMethod.GET, null)
    
    assertThat(response.statusCode).isEqualTo(HttpStatus.UNAUTHORIZED)
  }
  
  @Test
  fun `Alice uses her credentials to authenticate herself`() {
    val certificates = alice.getForList<Certificate>("https://localhost:$port/certificates/list", HttpMethod.GET, 
            HttpEntity<HttpHeaders>(headers("alice")))
    
    assertThat(certificates.statusCode).isEqualTo(HttpStatus.OK)
  }
  
  @Test
  fun `Alice requests a certificate for Bob`() {
    val keyPair   = ca.keyPair()
    val csr       = ca.CSR(keyPair, ca.principal("bob"))
    val request   = HttpEntity(CertificateSigningRequest(csr), headers("alice"))
    val response  = alice.exchange("https://localhost:$port/certificates/csr", HttpMethod.POST, request, Certificate::class.java)
    
    assertThat(response.statusCode.value()).isEqualTo(200)
    assertThat(response.body).isNotNull
   
    val certificate   = ca.unpem(response.body!!.certificatePem) as X509Certificate
    val caCertificate = defaultKeyStore().resource("classpath:ca_truststore.jks").getCertificate("CA")
    val keyStore      = defaultKeyStore().empty().put("BOB", keyPair.private, certificate = certificate)
    val trustStore    = defaultKeyStore().empty().put("BOB", certificate).put("CA", caCertificate)
    val bob           = ClientConfiguration.sslRestTemplate(keyStore, trustStore)

    bob.getForEntity("https://localhost:$port/greeting", Greeting::class.java).run {
      assertThat(statusCode).isEqualTo(HttpStatus.OK)
      assertThat(body?.content).isEqualTo("Hello, World")
      assertThat(body?.id).isPositive()
    }
  }
  
  private fun headers(username: String?, passwd: String? = null) = HttpHeaders().apply {
    contentType = MediaType.APPLICATION_JSON
    accept = listOf(MediaType.APPLICATION_JSON)
    if (username != null) setBasicAuth(username, String(passwordOrDefault(passwd)))
  }
}