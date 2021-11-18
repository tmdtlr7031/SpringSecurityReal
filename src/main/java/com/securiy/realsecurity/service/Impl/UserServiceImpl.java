package com.securiy.realsecurity.service.Impl;

import com.securiy.realsecurity.domain.Account;
import com.securiy.realsecurity.repository.UserRepository;
import com.securiy.realsecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;

@RequiredArgsConstructor
@Service("userService")
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    @Transactional(rollbackOn = Exception.class)
    @Override
    public void createUser(Account account) {
        userRepository.save(account);
    }
}
