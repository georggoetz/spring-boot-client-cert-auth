package de.georgg

import de.georgg.CertificateAuthority.Companion.provider
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import org.springframework.stereotype.Component
import java.io.StringReader
import java.io.StringWriter
import java.lang.StringBuilder
import java.math.BigInteger
import java.security.*
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.util.*
import javax.security.auth.x500.X500Principal

@Component
class CertificateAuthority {
  
  companion object {
    val provider = BouncyCastleProvider()
  }
  
  fun keyPair(keyStrength: Int = 2048): KeyPair = KeyPairGenerator.getInstance("RSA").apply { 
    initialize(keyStrength, SecureRandom())
  }.generateKeyPair()
  
  fun principal(cn: String, o: String? = null, ou: String? = null, c: String? = null, st: String? = null, l: String? = null): Principal {
    val sb = StringBuilder()
    sb.append("CN=$cn")
    o?.let  { sb.append("O=$it") }
    ou?.let { sb.append("OU=$it") }
    c?.let  { sb.append("C=$it") }
    st?.let { sb.append("ST=$it") }
    l?.let  { sb.append("L=$it") }
    return X500Principal(sb.toString())
  }
  
  fun selfSign(keyPair: KeyPair, principalDN: Principal) = 
          sign(keyPair.private, keyPair.public, principalDN, principalDN)
  
  fun sign(privateKey: PrivateKey, subjectPublicKey: PublicKey, issuerDN: Principal, subjectDN: Principal): X509Certificate {
    val now               = System.currentTimeMillis()
    val issuer            = issuerDN.x500Name()
    val serial            = BigInteger(1024, SecureRandom.getInstance("SHA1PRNG")) 
    val notBefore         = Date(now)
    val calendar          = Calendar.getInstance(); calendar.time = notBefore; calendar.add(Calendar.YEAR, 1)
    val notAfter          = calendar.time
    val subject           = subjectDN.x500Name()
    val x509Builder       = JcaX509v3CertificateBuilder(issuer, serial, notBefore, notAfter, subject, subjectPublicKey)
    val signer            = JcaContentSignerBuilder("SHA256WithRSA").setProvider(provider).build(privateKey)
    val certificateHolder = x509Builder.build(signer)
    return JcaX509CertificateConverter().getCertificate(certificateHolder)
  }
  
  fun signCSR(pem: String, privateKey: PrivateKey, issuerDN: Principal, subjectDN: Principal? = null): X509Certificate {
    val csr       = JcaPKCS10CertificationRequest(unpem(pem) as PKCS10CertificationRequest)
    val verifier  = JcaContentVerifierProviderBuilder().build(csr.subjectPublicKeyInfo)
    if (!csr.isSignatureValid(verifier)) {
      throw SignatureException("Signature is invalid")
    }
    val subject = subjectDN ?: X500Principal(csr.subject.encoded)
    return sign(privateKey, csr.publicKey, issuerDN, subject) 
  }
  
  fun CSR(keyPair: KeyPair, subjectDN: Principal): String {
    val subject     = subjectDN.x500Name()
    val csrBuilder  = JcaPKCS10CertificationRequestBuilder(subject, keyPair.public)
    val signer      = JcaContentSignerBuilder("SHA256WithRSA").setProvider(provider).build(keyPair.private)
    val csr         = csrBuilder.build(signer)
    return pem(csr)
  }
  
  fun pem(obj: Any): String = StringWriter().use { sw ->
    JcaPEMWriter(sw).use { w ->
      w.writeObject(obj)
    }
    return sw.toString()
  }
  
  fun unpem(s: String): Any = StringReader(s).use { sr ->
    PEMParser(sr).use { pp ->
      val any =  pp.readObject()
      when (any) {
        is X509CertificateHolder -> JcaX509CertificateConverter().getCertificate(any)
        else -> any
      }
    }
  }
  
  private fun Principal.x500Name() = X500Name.getInstance((this as X500Principal).encoded)
}