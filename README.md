# 스프링시큐리티 실전편
- (3) 사용자 DB등록 및 PasswordEncoder
  - Spring Security 5 부터 평문 암호화르 위해 `PasswordEncoderFactories.createDelegatingPasswordEncoder();`를 이용하여 빠르게 구현 가능 (`DelegatingPasswordEncoder`이용함)
  - 하지만 default 값이 `bcrypt`를 이용하여 인코딩을 하게 된다. 그럼 sha256으로 바꾸고싶다면..?
  - SecurityConfig.java에서 `new StandardPasswordEncoder()`이렇게 작성하면 되지만 @Deprecated 되었다. 안에 들어가 확인해보니
  - `DelegatingPasswordEncoder`구현체르 사용하도로 가이드 되어 있다.
  - 즉, 기존에 암호화가 안되어 있다며 `bcrypt`를 따르고, 기존에 다른 암호화 방식으로 되어 있는 형식 (ex. {sha256}asjdkajsnkjc)들을 마이그레이셔 작업할떄는 유용할 것.. 
  - 물론 평문 Or 해당 포맷이 아닌 경우에 `DelegatingPasswordEncoder`을 이용하면 Exception날 것으로 예상된다.
  - 참고
   > https://stackoverflow.com/questions/65796088/how-override-the-default-bcryptpasswordencoder-created-through-passwordencoderfa
   > https://www.inflearn.com/questions/349010
 
```java
// DelegatingPasswordEncoder.java

private PasswordEncoder defaultPasswordEncoderForMatches = new UnmappedIdPasswordEncoder();

@Override
public boolean matches(CharSequence rawPassword, String prefixEncodedPassword) {
	if (rawPassword == null && prefixEncodedPassword == null) {
		return true;
	}
	String id = extractId(prefixEncodedPassword);
	PasswordEncoder delegate = this.idToPasswordEncoder.get(id);
	if (delegate == null) {
		return this.defaultPasswordEncoderForMatches.matches(rawPassword, prefixEncodedPassword);
	}
	String encodedPassword = extractEncodedPassword(prefixEncodedPassword);
	return delegate.matches(rawPassword, encodedPassword);
}
```
 
```java
// UnmappedIdPasswordEncoder.java

// Default {@link PasswordEncoder} that throws an exception telling that a suitable
// {@link PasswordEncoder} for the id could not be found.
private class UnmappedIdPasswordEncoder implements PasswordEncoder {

	@Override
	public String encode(CharSequence rawPassword) {
		throw new UnsupportedOperationException("encode is not supported");
	}

	@Override
	public boolean matches(CharSequence rawPassword, String prefixEncodedPassword) {
		String id = extractId(prefixEncodedPassword);
		throw new IllegalArgumentException("There is no PasswordEncoder mapped for the id \"" + id + "\"");
	}
}
```

---


- (4) DB 연동 인증 처리(1) - CustomUserDetailsService
  - 기존에 메모리 방식은 테스트용으로 사용 가능할 것 같다.
  - UserDetails 인터페이스를 위해 User 클래스를 상속받는 AccountContext 클래스 생성
  - 스프링 시큐리티가 최종적으로 UserDetailsService르 이용하여 인증처리를 한다.
  - 여기엔 UserDetails가 필요하다. 그래서 UserDetails를 구현한 User 클래스를 상속받아 커스텀한 AccountContext를 만들게 된 것이다.

  ```java
   @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 메모리 방식 인증처리
        String password = passwordEncoder().encode("1111");
        auth.inMemoryAuthentication().withUser("user").password(password).roles("USER","MANAGER","ADMIN");
        auth.inMemoryAuthentication().withUser("manager").password(password).roles("MANAGER","ADMIN");
        auth.inMemoryAuthentication().withUser("admin").password(password).roles("ADMIN");

        // DB 정보를 통한 인증처리
        auth.userDetailsService(customUserDetailsService);
    }
  ```

- (5) DB 연동 인증 처리(2) - CustomAuthenticationProvider
  - 첫번째 생성자는 AuthenticationManager에게 전달할 때 인증필터가 해당 생성자를 통해 사용자 정보를 넘기게 된다.
  - 반면 두번째 생성자는 인증에 대한 검증이 완료된 경우 사용한다.
  ```java
 	 public UsernamePasswordAuthenticationToken(Object principal, Object credentials) {
		super(null);
		this.principal = principal;
		this.credentials = credentials;
		setAuthenticated(false);
	}

	public UsernamePasswordAuthenticationToken(Object principal, Object credentials,
			Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.principal = principal;
		this.credentials = credentials;
		super.setAuthenticated(true); // must use super, as we override
	}
  ```
  
  
  - 문제발생
   - CustomAuthenticationProvider를 작성하고 SecurityConfig애서 DI를 통해서 사용하려 했지만 순환참조 오류가 발생했다. (생성자 주입의 중요성!!)
   - `SecurityConfig`에서 `customAuthenticationProvider`를 DI 하기 위해 `customAuthenticationProvider`를 @Component를 통해 빈으로 등록하지만 `customAuthenticationProvider`에서 `passwordEncoder`를 DI하기 위해 `SecurityConfig`를 바라보기 때문이었다.
   - @Component를 빼고 `SecurityConfig`에서 별도로 빈을 만들자


  ```java
    @Component
    @RequiredArgsConstructor
    public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService customUserDetailsService;
    private final PasswordEncoder passwordEncoder;

    /**
     * 인증에 대한 검증 부분
     * - authentication : 사용자가 입력한 아이디, pw 등이 담겨있음
     * - id, pw 외 다른 검증도 추가할 수 있다.
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
	String username = authentication.getName();
	String password = (String) authentication.getCredentials();

	AccountContext accountContext = (AccountContext) customUserDetailsService.loadUserByUsername(username);

	// 입력한 패스워드와 DB상의 패스워드 일치 여부
	if (!passwordEncoder.matches(password, accountContext.getPassword())) {
	    throw new BadCredentialsException("BadCredentialsException");
	}

	// 최종적으로 인증에 성공한 정보를 담아 Provider를 호출한 AuthenticationProcessingFilter에게 반환
	UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(accountContext.getAccount(), null, accountContext.getAuthorities());
	return authenticationToken;
    }

    /**
     * 파라미터로 넘어온 authentication이 UsernamePasswordAuthenticationToken과 일치하면
     * CustomAuthenticationProvider가 인증을 처리한다.
     */
    @Override
    public boolean supports(Class<?> authentication) {
	return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
  }
  
  ```
  ```java
    @EnableWebSecurity
    @RequiredArgsConstructor
    public class SecurityConfig extends WebSecurityConfigurerAdapter {

      private final UserDetailsService customUserDetailsService;
      private final AuthenticationProvider customAuthenticationProvider;

      @Override
      protected void configure(AuthenticationManagerBuilder auth) throws Exception {
          auth.authenticationProvider(customAuthenticationProvider);
      }
      
      @Bean
      public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
      }
    
    // ------------------------ 변경 후
    // CustomAuthenticationProvider.java => @Component 제거
    
    // SecurityConfig.java
    // private final AuthenticationProvider customAuthenticationProvider; 제거
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authenticationProvider());
    }
      
    @Bean
    public AuthenticationProvider authenticationProvider() {
        return new CustomAuthenticationProvider(customUserDetailsService, passwordEncoder());
    }
    
  ```
  - 기존 방식과의 차이점?
    - `auth.userDetailsService(customUserDetailsService);` 
      - DaoAuthenticationProvider가 customUserDetailsService를 이용
      - 인증을 시도하는 사용자의 정보가 DB에 존재하는지를 검증하는 비즈니스 로직을 담당
    - `auth.authenticationProvider(authenticationProvider());` 
      - CustomAuthenticationProvider를 통해 customUserDetailsService를 이용
      - 실제 사용자의 인증 처리를 위한  비즈니스 로직을 구현하는 역할 (customUserDetailsService보다 넓은 개념)
   - 인증 검증(ex.패스워드 검증)같이 특별한 과정이 필요하다면 Provider를 이용하고 그게 아니라면 DaoAuthenticationProvider만 간단하게 사용해도 무방하다. 아니면 둘 다 사용해도 되고..

