package com.mv.authentication.service;


import jakarta.validation.Valid;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.mv.authentication.controller.dto.SignupRequest;
import com.mv.authentication.domain.User;
import com.mv.authentication.exceptions.DuplicateException;
import com.mv.authentication.exceptions.NotFoundException;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

	private final PasswordEncoder passwordEncoder;
	
	//In real time we connect to database here
	List<User> userList = new ArrayList<User>();

	public UserDetailsServiceImpl(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public UserDetails loadUserByUsername(String email) {
		User user = null;
		for (User u : userList) {
			if (u.email().equals(email)) {
				user = u;
			}
		}
		if (user == null) {
			throw new NotFoundException(String.format("User does not exist, email: %s", email));
		}

		return org.springframework.security.core.userdetails.User.builder().username(user.email())
				.password(user.password()).build();
	}

	public void signup(@Valid SignupRequest requestDto) {
		String email = requestDto.email();
		for (User user : userList) {
			if (user.email().equals(email)) {
				throw new DuplicateException(String.format("User with the email address '%s' already exists.", email));
			}
		}

		String hashedPassword = passwordEncoder.encode(requestDto.password());
		User user = new User(requestDto.name(), email, hashedPassword);
		userList.add(user);
	}
}
