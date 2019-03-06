package de.georgg

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.stereotype.Component

@Component
@ConfigurationProperties(prefix = "app.security")
class SecurityProperties {
  
  class CredentialProperties {
    lateinit var password: String
    lateinit var roles: Array<String>
  }
  
  lateinit var credentials: HashMap<String, CredentialProperties>
}