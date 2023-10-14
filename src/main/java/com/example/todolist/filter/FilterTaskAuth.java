package com.example.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.todolist.user.IUserRepository;

import at.favre.lib.crypto.bcrypt.BCrypt;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

  @Autowired
  private IUserRepository userRepository;

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {

    var servletPath = request.getServletPath();

    if( servletPath.startsWith("/tasks") ) {
      // Get Authorization from header
      var auth = request.getHeader("Authorization").substring("Basic".length()).trim();

      // Decode the authorization
      byte[] authDecoded = Base64.getDecoder().decode(auth);
      var authString = new String(authDecoded);

      // Ge the credentials from authorization
      String[] credentials = authString.split(":");
      String userName = credentials[0];
      String password = credentials[1];

      // Validate user
      var user = this.userRepository.findByUsername(userName);
      if(user == null) {
        response.sendError(401);
      } else {
        // Validade password
        var pwdVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());

        if( pwdVerify.verified ) {
          request.setAttribute("userId", user.getId());
          filterChain.doFilter(request, response);
        } else {
          response.sendError(401);
        }
      }
    } else {
      filterChain.doFilter(request, response);
    }
  }
}
