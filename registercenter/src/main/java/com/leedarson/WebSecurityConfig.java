package com.leedarson;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * 注册中心太重要了，需要增加所属的安全配置<br>
 * 
 * @author howard
 * @Create_Date: 2019年5月16日下午7:24:40
 * @Modified_By: howard
 * @Modified_Date: 2019年5月16日下午7:24:40
 * @Why_and_What_is_modified: <br>
 */
@EnableWebSecurity
class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http.csrf().ignoringAntMatchers("/eureka/**");
		super.configure(http);
	}
}
