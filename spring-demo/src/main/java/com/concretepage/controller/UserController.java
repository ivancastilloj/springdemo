package com.concretepage.controller;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.concretepage.dao.UserDAO;
import com.concretepage.entity.UserInfo;
import com.concretepage.service.IUserService;

@Controller
@RequestMapping("/user")
public class UserController {
	@Autowired
	private  IUserService service;
	@RequestMapping(value="/home")
	public String home(ModelMap model, Authentication authentication) {
		authentication.getPrincipal();
		model.addAttribute("user", service.getDataByUserName(authentication.getName()));
 		return "user-info";
 	}
	@RequestMapping(value="/error")
	public String error() {
 		return "access-denied";
 	}@RequestMapping(value="/felicidades")
	public String felicidades() {
 		return "congratulations";
}	
 	  protected void doPost(HttpServletRequest request,
 	            HttpServletResponse response) throws ServletException, IOException {
 	 
 	        String userName = request.getParameter("userName");
 	        String password = request.getParameter("password");
 	       BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
 	      
 	     password= encoder.encode(password).toString();
 	        String role = "ROLE_ADMIN";
 	        String fullname = request.getParameter("fullname");
 	        String country = request.getParameter("country");
 	       int enabled =1;
 	 
 	        HttpSession session = request.getSession(true);
 	        try {
 	            UserInfo userInfo = new UserInfo();
 	            userInfo.addUser(userName, password, role, fullname, country,enabled);
 	            response.sendRedirect("Success");
 	        } catch (Exception e) {
 	 
 	            e.printStackTrace();
 	        }
 	 
 	    }
 	}
