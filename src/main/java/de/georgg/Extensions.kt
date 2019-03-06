package de.georgg

import org.springframework.core.ParameterizedTypeReference
import org.springframework.http.HttpEntity
import org.springframework.http.HttpMethod
import org.springframework.http.ResponseEntity
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.User
import org.springframework.util.ResourceUtils
import org.springframework.web.client.RestTemplate
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate

fun defaultKeyStore(): KeyStore = KeyStore.getInstance(KeyStore.getDefaultType())

fun KeyStore.resource(filename: String, passwd: String? = null): KeyStore {
  this.load(ResourceUtils.getFile(filename).inputStream(), passwordOrDefault(passwd))
  return this
}

fun KeyStore.empty(passwd: String? = null): KeyStore {
  this.load(null, passwordOrDefault(passwd))
  return this
}

fun KeyStore.put(alias: String, privateKey: PrivateKey, passwd: String? = null,
                 certificate: java.security.cert.Certificate): KeyStore {
  this.setKeyEntry(alias, privateKey, passwordOrDefault(passwd), arrayOf(certificate))
  return this
}

fun KeyStore.put(alias: String, certificate: java.security.cert.Certificate): KeyStore {
  this.setCertificateEntry(alias, certificate)
  return this
}

data class PrivateKeyEntry(val privateKey: PrivateKey, val certificate: X509Certificate)

fun KeyStore.privateKey(alias: String, passwd: String? = null): PrivateKeyEntry {
  val entry = this.getEntry(alias, KeyStore.PasswordProtection(passwordOrDefault(passwd))) as KeyStore.PrivateKeyEntry
  return PrivateKeyEntry(entry.privateKey, entry.certificate as X509Certificate)
}

val Authentication.username: String
  get() = (this.principal as User).username

fun <T: Any> RestTemplate.getForList(url: String, method: HttpMethod, requestEntity: HttpEntity<*>?): ResponseEntity<List<T>> {
  return this.exchange(url, method, requestEntity, object: ParameterizedTypeReference<List<T>>() {}) as ResponseEntity<List<T>>
}

fun passwordOrDefault(passwd: String?): CharArray = (passwd ?: "changeit").toCharArray()