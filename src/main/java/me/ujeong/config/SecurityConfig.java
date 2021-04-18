package me.ujeong.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter{
    @Override
    public void configure(WebSecurity web) { //h2에 접근하기 위해 h2 컨솔 하위 모든 요청은  spring security 로직을 수행하지 않도록 설정
        web.ignoring()
                .antMatchers(
                        "/h2-console/**"
                        ,"/favicon.ico"
                        ,"/error"
                );
    }
    
	
	@Override
	protected void configure(HttpSecurity http) throws Exception{
		http
				.authorizeRequests()	//httpServletRequest를 사용하는 요청들에 대한 접근 제한을 설정하겠다는 의미
				.antMatchers("/api/hello").permitAll() ///api/hello 에 대한 요청은 인증없이 접근을 허용하겠다.
				.anyRequest().authenticated();// 나머지 요청들에 대해서는 인증을 받아야한다.
		
		
	}
	
	
}
