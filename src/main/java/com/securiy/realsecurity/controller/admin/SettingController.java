package com.securiy.realsecurity.controller.admin;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class SettingController {

    @GetMapping("/config")
    public String config() {
        return "admin/config";
    }
}
