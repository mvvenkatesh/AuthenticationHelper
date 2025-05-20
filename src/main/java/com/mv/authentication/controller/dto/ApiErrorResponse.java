package com.mv.authentication.controller.dto;

import io.swagger.v3.oas.annotations.media.Schema;

public record ApiErrorResponse(
    int errorCode,
    String description) {

}
