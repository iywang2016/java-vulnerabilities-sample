package fr.lernejo.sqlinj.user;

import fr.lernejo.sqlinj.user.dto.LoginAndPassword;
import fr.lernejo.sqlinj.user.dto.User;
import fr.lernejo.sqlinj.user.dto.UserDetailsForInscription;
import fr.lernejo.sqlinj.user.dto.UserEntity;
import fr.lernejo.sqlinj.user.exception.UnauthorizedUser;
import org.checkerframework.checker.tainting.qual.Tainted;
import org.checkerframework.checker.tainting.qual.Untainted;
import org.springframework.stereotype.Service;
import org.springframework.util.SerializationUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

@Service
public class UserService {

    private final SecurityService securityService;
    private final UserRepository userRepository;

    UserService(SecurityService securityService, UserRepository userRepository) {
        this.securityService = securityService;
        this.userRepository = userRepository;
    }

    /**
     * Returns user information from login attempt
     * @param  authorizationHeader: base64 encoded auth, should be safe
     * @return  User: potentially dangerous user (username, f/n, l/n)
     */
     User authenticate( String authorizationHeader) {
         Optional<User> authenticatedUser = getAuthenticatedUser(authorizationHeader);
        return authenticatedUser.orElseThrow(() -> new UnauthorizedUser());
    }

    /**
     * Returns true if user login is valid (i.e. User exists in repo), false otherwise
     * @param  authorizationHeader: base64 encoded should be safe?
     * @return  boolean: if user login valid
     */
    public  boolean isAuthenticated( String authorizationHeader) {
        return getAuthenticatedUser(authorizationHeader).isPresent();
    }

    /**
     * Processes authorization header and returns user (username, f/n, l/n) if
     * login attempt valid, otherwise null
     * @param  authorizationHeader: base64 encoded, safe?
     * @return  Optional<User>: user of login attempt
     */
     Optional<User> getAuthenticatedUser( String authorizationHeader) {
         LoginAndPassword loginAndPassword = securityService.extractFromHeader(authorizationHeader);
         Optional<UserEntity> user = userRepository.findUserByLogin(loginAndPassword.login());
        // Checks that username exists and attempted password matches stored encoded password for user
        if (user.isPresent() && securityService.match(loginAndPassword.password(), user.get().encodedPassword())) {
            return user.map(this::mapFromEntity);
        } else {
            return Optional.empty();
        }
    }

    /**
     * Creates User object from UserEntity object
     * @param  userEntity: all user info (login, password, names)
     * @return  User: user login (username, f/n, l/n)
     */
    private  User mapFromEntity( UserEntity userEntity) {
        return new User(
            userEntity.login(),
            userEntity.firstName(),
            userEntity.lastName()
        );
    }

    /**
     * NO idea what this method does
     * @param  userDetailsForInscription: probably unsanitized
     * @return  User: probably also unsanitized
     */
     User inscription(UserDetailsForInscription userDetailsForInscription) {
         UserEntity user = userRepository.createUser(mapToEntity(userDetailsForInscription));
        return mapFromEntity(user);
    }

    private UserEntity mapToEntity(UserDetailsForInscription userDetailsForInscription) {
        return new UserEntity(
            userDetailsForInscription.login(),
            securityService.encodePassword(userDetailsForInscription.password()),
            userDetailsForInscription.firstName(),
            userDetailsForInscription.lastName()
        );
    }

    String obfuscate(String id) {
        return Base64.getEncoder().encodeToString(SerializationUtils.serialize(id));
    }

    public String desobfuscate(String b64payload) {
        return (String) SerializationUtils.deserialize(Base64.getDecoder().decode(b64payload));
    }
}
