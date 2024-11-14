package me.isra.users_auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import io.github.cdimascio.dotenv.Dotenv;

@SpringBootApplication
public class UsersAuthApplication {

	public static void main(String[] args) {
		Dotenv.configure().load();
		SpringApplication.run(UsersAuthApplication.class, args);
	}

}
