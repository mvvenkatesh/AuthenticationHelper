package com.mv.authentication.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mv.authentication.controller.dto.ApiErrorResponse;
import com.mv.authentication.exceptions.AccessDeniedException;
import com.mv.authentication.helper.JwtHelper;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

	private final UserDetailsService userDetailsService;
	private final ObjectMapper objectMapper;

	public JwtAuthFilter(@Lazy UserDetailsService userDetailsService, ObjectMapper objectMapper) {
		this.userDetailsService = userDetailsService;
		this.objectMapper = objectMapper;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		try {
			String authHeader = request.getHeader("Authorization");

			String token = null;
			String username = null;
			if (authHeader != null && authHeader.startsWith("Bearer ")) {
				token = authHeader.substring(7);
				username = JwtHelper.extractUsername(token);
			}

			if (token == null) {
				filterChain.doFilter(request, response);
				return;
			}

			if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
				UserDetails userDetails = userDetailsService.loadUserByUsername(username);
				if (JwtHelper.validateToken(token, userDetails)) {
					UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
							userDetails, null, null);
					authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
					SecurityContextHolder.getContext().setAuthentication(authenticationToken);
				}
			}

			filterChain.doFilter(request, response);
		} catch (AccessDeniedException e) {
			ApiErrorResponse errorResponse = new ApiErrorResponse(HttpServletResponse.SC_FORBIDDEN, e.getMessage());
			response.setStatus(HttpServletResponse.SC_FORBIDDEN);
			response.getWriter().write(toJson(errorResponse));
		}
	}

	private String toJson(ApiErrorResponse response) {
		try {
			return objectMapper.writeValueAsString(response);
		} catch (Exception e) {
			return "";
		}
	}
}
