package de.georgg

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.MediaType
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod
import org.springframework.web.bind.annotation.RestController
import java.security.Security
import java.util.*

data class Certificate(val certificateId: String, val certificatePem: String, val certificateUrl: String)
data class CertificateSigningRequest(val certificateSigningRequestPem: String)

@RestController
@RequestMapping("/certificates", produces = [MediaType.APPLICATION_JSON_VALUE])
open class CertificateController {
  init {
    Security.addProvider(CertificateAuthority.provider)
  }
  
  private val certificateRepo = HashMap<String, LinkedList<Certificate>>()

  @Value("\${server.ssl.key-store}")
  private lateinit var caKeyStore: String

  @Autowired
  private lateinit var ca: CertificateAuthority

  @RequestMapping("/csr", method = [RequestMethod.POST], consumes = [MediaType.APPLICATION_JSON_VALUE])
  fun signCSR(@RequestBody(required = true) csr: CertificateSigningRequest): Certificate {
    val user                      = SecurityContextHolder.getContext().authentication.username
    val (privateKey, cacert)      = defaultKeyStore().resource(caKeyStore).privateKey("CA")
    val issuerDN                  = cacert.issuerX500Principal
    val subjectDN                 = ca.principal(user)
    val pem                       = csr.certificateSigningRequestPem
    val certificate               = ca.signCSR(pem, privateKey, issuerDN, subjectDN)
    val serialNumber              = certificate.serialNumber.toString()
    val certificatePem            = ca.pem(certificate)
    val certificateUrl            = "/certificates/$serialNumber"

    return Certificate(serialNumber, certificatePem, certificateUrl).also {
      certificateRepo.computeIfAbsent(user) { _ -> LinkedList() }.add(it)
    }
  }

  @RequestMapping("/list", method = [RequestMethod.GET])
  fun list(): List<Certificate> {
    val user = SecurityContextHolder.getContext().authentication.username
    return certificateRepo[user] ?: emptyList()
  }
}