# 스프링시큐리티 실전편
- 3) 사용자 DB등록 및 PasswordEncoder
  - Spring Security 5 부터 평문 암호화르 위해 `PasswordEncoderFactories.createDelegatingPasswordEncoder();`를 이용하여 빠르게 구현 가능 (`DelegatingPasswordEncoder`이용함)
  - 하지만 default 값이 `bcrypt`를 이용하여 인코딩을 하게 된다. 그럼 sha256으로 바꾸고싶다면..?
  - SecurityConfig.java에서 `new StandardPasswordEncoder()`이렇게 작성하며 되지만 @Deprecated 되었다. 안에 들어가 확인해보니
  - `DelegatingPasswordEncoder`구현체르 사용하도로 가이드 되어 있다.
  - 즉, 기존에 암호화가 안되어 있다며 `bcrypt`를 따르고, 기존에 다른 암호화 방식으로 되어 있는 형식 (ex. {sha256}asjdkajsnkjc)들을 마이그레이셔 작업할떄느 유용할 것.. 
  - 물론 평문 Or 해당 포맷이 아닌 경우 `DelegatingPasswordEncoder`을 이용하면 Exception날 것으로 예상된다.
 
 '''   
	
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
  '''
