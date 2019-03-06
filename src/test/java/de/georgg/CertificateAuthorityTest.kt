package de.georgg

import org.assertj.core.api.Assertions.assertThat
import org.junit.Before
import org.junit.BeforeClass
import org.junit.Test
import org.springframework.core.io.ClassPathResource
import java.nio.file.Files
import java.security.Security

class CertificateAuthorityTest {
  
  companion object {
    @BeforeClass
    @JvmStatic
    fun beforeAllTests() {
      Security.addProvider(CertificateAuthority.provider)
    }
  }
  
  private lateinit var ca: CertificateAuthority
  
  @Before
  fun beforeEachTest() {
    ca = CertificateAuthority()
  }
  
  @Test
  fun `Create self signed certificate`() {
    val issuer = "ISSUER"
    val principal = ca.principal(issuer)
    val certificate = ca.selfSign(ca.keyPair(), principal)
    
    assertThat(certificate.type).isEqualTo("X.509")
    assertThat(certificate.issuerDN.name).isEqualTo("CN=$issuer")
    assertThat(certificate.issuerDN).isEqualTo(certificate.subjectDN)
  }
  
  @Test
  fun `Create certificate signing request CSR`() {
    val issuer = "ISSUER"
    val principal = ca.principal(issuer)
    val csr = ca.CSR(ca.keyPair(), principal)
    
    assertThat(csr).startsWith("-----BEGIN CERTIFICATE REQUEST-----")
  }
  
  @Test
  fun `Sign certificate signing request CSR`() {
    val keyPair = ca.keyPair()
    val issuerDN = ca.principal("CA")
    val pem = String(Files.readAllBytes(ClassPathResource("alice.csr").file.toPath()))
    val certificate = ca.signCSR(pem, keyPair.private, issuerDN)

    assertThat(certificate.type).isEqualTo("X.509")
    assertThat(certificate.issuerDN.name).isEqualTo(issuerDN.name)
    assertThat(certificate.subjectDN.name).isEqualTo("CN=Alice, O=ACME Org, C=de")
  }
}