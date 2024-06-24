package fr.lernejo.sqlinj.user;

import fr.lernejo.sqlinj.user.dto.User;
import fr.lernejo.sqlinj.user.dto.UserDetailsForInscription;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.checkerframework.checker.tainting.qual.Tainted;
import org.checkerframework.checker.tainting.qual.Untainted;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
public class UserController {

    public static final String SESSION_ID_COOKIE_NAME = "session-id";

    private final Logger logger = LoggerFactory.getLogger(UserController.class);
    private final UserService userService;

    UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/api/login")
    @Untainted User authenticate(@RequestHeader("Authorization") @Untainted String authorizationHeader, @Untainted HttpServletResponse response) {
        @Tainted User user = userService.authenticate(authorizationHeader);
        @Untainted String sessionId = UUID.randomUUID().toString();
        response.addCookie(new Cookie(SESSION_ID_COOKIE_NAME, userService.obfuscate(sessionId)));
        logger.info("Starting session " + sessionId + " for " + user);
        return user;
    }

    @PostMapping("/api/registration")
    User registration(@RequestBody UserDetailsForInscription userDetailsForInscription) {
        return userService.inscription(userDetailsForInscription);
    }
}
