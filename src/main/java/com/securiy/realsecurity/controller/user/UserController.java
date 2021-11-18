package com.securiy.realsecurity.controller.user;

import com.securiy.realsecurity.domain.Account;
import com.securiy.realsecurity.domain.AccountDTO;
import com.securiy.realsecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;


    @GetMapping("/mypage")
    public String myPage() {
        return "user/mypage";
    }

    @GetMapping("/users")
    public String creatUser() {
        return "user/login/register";
    }

    @PostMapping("/users")
    public String creatUser(AccountDTO accountDTO) {

        ModelMapper modelMapper = new ModelMapper();
        Account account = modelMapper.map(accountDTO, Account.class); // DTO에 담긴 값을 Account Entitiy로 복사시켜줌
        account.setPassword(passwordEncoder.encode(account.getPassword())); // 비밀번호 인코딩
        userService.createUser(account);

        return "redirect:/";
    }
}
