package com.concretepage.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.concretepage.dao.UserDAO;
import com.concretepage.entity.UserInfo;

@Service
public class UserService implements IUserService {
	@Autowired
	private UserDAO userDAO;
	public UserInfo getDataByUserName(String userName) {
		return userDAO.getActiveUser(userName);
	}
}
