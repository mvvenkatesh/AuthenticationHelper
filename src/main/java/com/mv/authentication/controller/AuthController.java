
package com.mv.authentication.controller;

import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.mv.authentication.controller.dto.LoginRequest;
import com.mv.authentication.controller.dto.LoginResponse;
import com.mv.authentication.controller.dto.SignupRequest;
import com.mv.authentication.helper.JwtHelper;
import com.mv.authentication.service.UserDetailsServiceImpl;

@RestController
@RequestMapping(path = "/api/auth", produces = MediaType.APPLICATION_JSON_VALUE)
public class AuthController {

  private final AuthenticationManager authenticationManager;
  private final UserDetailsServiceImpl userService;

  public AuthController(AuthenticationManager authenticationManager, UserDetailsServiceImpl userService) {
    this.authenticationManager = authenticationManager;
    this.userService = userService;
  }

  @PostMapping("/signup")
  public ResponseEntity<Void> signup(@Valid @RequestBody SignupRequest requestDto) {
	userService.signup(requestDto);
    return ResponseEntity.status(HttpStatus.CREATED).build();
  }

  @PostMapping(value = "/login")
  public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
    try {
      authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.email(), request.password()));
    } catch (BadCredentialsException e) {
      throw e;
    }

    String token = JwtHelper.generateToken(request.email());
    return ResponseEntity.ok(new LoginResponse(request.email(), token));
  }

}