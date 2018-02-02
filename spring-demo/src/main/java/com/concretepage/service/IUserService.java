package com.concretepage.service;

import org.springframework.security.access.annotation.Secured;

import com.concretepage.entity.UserInfo;

public interface IUserService {
	@Secured ({"ROLE_ADMIN"})
	UserInfo getDataByUserName(String userName);
}
