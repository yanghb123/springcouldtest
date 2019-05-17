package com.leedarson;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;

@EnableZuulProxy
@SpringBootApplication
public class LdszuulApplication {

	public static void main(String[] args) {
		SpringApplication.run(LdszuulApplication.class, args);
	}
}
