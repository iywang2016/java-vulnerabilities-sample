package fr.lernejo.sqlinj.user;

import fr.lernejo.sqlinj.user.dto.LoginAndPassword;
import fr.lernejo.sqlinj.user.exception.InvalidAuthorizationHeader;
import org.checkerframework.checker.tainting.qual.Tainted;
import org.checkerframework.checker.tainting.qual.Untainted;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
class SecurityService {

    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder(10);
    private static final Pattern BASIC_AUTH_PATTERN = Pattern.compile("(?<login>[^:]+):(?<password>.+)");

    /**
     * Decodes authorization header to extract login and password attempt by user.
     * @param @Untainted authorizationHeader: base64-encoded header, should be safe
     * @return @Tainted LoginAndPassword: potentially dangerous login and password
     */
    @Tainted LoginAndPassword extractFromHeader(@Untainted String authorizationHeader) {
        @Tainted String loginAndPassword = new String(Base64.getDecoder().decode(authorizationHeader), StandardCharsets.UTF_8);
        @Tainted Matcher matcher = BASIC_AUTH_PATTERN.matcher(loginAndPassword);

        if (matcher.matches()) {
            return new LoginAndPassword(matcher.group("login"), matcher.group("password"));
        } else {
            throw new InvalidAuthorizationHeader();
        }
    }

    /**
     * Checks raw password (from login attempt) against encoded password
     * (as stored in user repo. when user created)
     * @param @Tainted rawPassword: unsanitized password entered by user
     * @param @Untainted encodedPassword: base64 encoded, should be safe
     * @return @Tainted boolean: whether raw and encoded passwords match
     */
    @Tainted boolean match(@Tainted String rawPassword, String encodedPassword) {
        return passwordEncoder.matches(rawPassword, encodedPassword);
    }

    /**
     * Encodes raw password entered by user.
     * @param @Tainted rawPassword: unencoded password, may contain dangerous
     * SQL sequences
     * @return @Untainted String: encoded password, should be temporarily "sanitized"
     * due to encoding
     */
    @Untainted String encodePassword(@Tainted String rawPassword) {
        return sanitize(passwordEncoder.encode(rawPassword));
    }

    @Untainted String sanitize(@Tainted String str) {
        @SuppressWarnings("tainting")//doesn't actually sanitize, just a placeholder
        @Untainted String result = str;
        return result;
    }
}
