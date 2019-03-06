package de.georgg

import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.authorization.AuthenticatedReactiveAuthorizationManager.authenticated
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException

@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
open class SecurityConfiguration {

  @Configuration
  @Order(1)
  open class BasicAuthSecurityConfiguration(val securityProperties: SecurityProperties) : WebSecurityConfigurerAdapter() {

    override fun configure(http: HttpSecurity) {
      http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
      
      http    
              .csrf().disable()    // POST only works without csrf?!?
              .authorizeRequests()
                .anyRequest()
                .authenticated()
              .and()
                .antMatcher("/certificates/**")
                .httpBasic()
    }

    override fun configure(auth: AuthenticationManagerBuilder) {
      val cfg = auth.inMemoryAuthentication()
      securityProperties.credentials.forEach {
        cfg
                .withUser(it.key)
                .password("{noop}" + it.value.password) // Because passwords are stored in plain text use the NoOpPasswordEncoder.
                .roles(it.value.roles.joinToString())
      }
    }
  }  

  @Configuration
  open class X509SecurityConfiguration(val securityProperties: SecurityProperties) : WebSecurityConfigurerAdapter() {

    @Value("\${app.security.x509.subject-principal-regex}")
    private lateinit var subjectPrincipalRegex: String

    override fun configure(http: HttpSecurity) {
      http
              .authorizeRequests()
                .anyRequest().authenticated().and().x509()
                  .subjectPrincipalRegex(subjectPrincipalRegex)
                  .userDetailsService(userDetailsService())
    }

    @Bean
    override fun userDetailsService() = UserDetailsService {
      val username = it.toLowerCase()
      val credentials = securityProperties.credentials[username]
      credentials?.let {
        User(username, it.password, AuthorityUtils.createAuthorityList(*it.roles))
      } ?: throw UsernameNotFoundException("User $username not found")
    }
  }
}