package de.georgg

import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication
import java.security.Security

@SpringBootApplication
open class Application

fun main(args: Array<String>) {
  Security.addProvider(CertificateAuthority.provider)
  SpringApplication.run(Application::class.java, *args)
}