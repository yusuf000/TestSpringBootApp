package com.example.TestSpringBootApp.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Calendar;

@RestController
@RequestMapping("/test2")
public class Test2Controller {

    @PostMapping("/serverTime")
    public String requestLicense() {
        return Calendar.getInstance().getTime().toString();
    }
}
