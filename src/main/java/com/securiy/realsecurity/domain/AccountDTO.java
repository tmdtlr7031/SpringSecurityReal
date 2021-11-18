package com.securiy.realsecurity.domain;

import lombok.Data;

import javax.persistence.GeneratedValue;
import javax.persistence.Id;

@Data
public class AccountDTO {

    private String username;
    private String password;
    private String email;
    private String age;
    private String role;
}
