package com.mv.authentication.controller.dto;

public record LoginResponse(
    String email,
    String token) {

}
