package me.isra.users_auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;


@SpringBootApplication
public class UsersAuthApplication {

	public static void main(String[] args) {
		System.out.println("DATABASE_URL: " + System.getenv("DB_URL"));
		SpringApplication.run(UsersAuthApplication.class, args);
	}

}
