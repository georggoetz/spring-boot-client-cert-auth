package de.georgg

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.util.concurrent.atomic.AtomicLong

data class Greeting(val id: Long, val content: String)

@RestController
open class GreetingController {
  
  private val counter = AtomicLong()

  @GetMapping("/greeting")
  fun greeting(@RequestParam(value = "name", defaultValue = "World") name: String) =
          Greeting(counter.incrementAndGet(), "Hello, $name")
}