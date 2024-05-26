package com.gangulwar.Jwt_Implementation.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class EndpointController {

    @GetMapping("/checkJWT")
    public String checkJwt(){
        return "JWT verified!";
    }
}
