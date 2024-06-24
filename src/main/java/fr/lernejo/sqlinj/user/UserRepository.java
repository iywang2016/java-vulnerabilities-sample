package fr.lernejo.sqlinj.user;

import fr.lernejo.sqlinj.user.dto.UserEntity;
import fr.lernejo.sqlinj.user.exception.TooManyUsersWithTheSameLogin;
import org.checkerframework.checker.tainting.qual.Tainted;
import org.checkerframework.checker.tainting.qual.Untainted;
import org.springframework.stereotype.Repository;

import javax.sql.DataSource;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Repository
class UserRepository {

    private final DataSource dataSource;

    UserRepository(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    /**
     * Creates a user in the database from the passed UserEntity record by
     * SQL query.
     * @param @Tainted userEntity: unsanitized user created by client,
     * with unsanitized login/password/name
     * @return @Tainted UserEntity: same userEntity as passed in, not modified
     */
    @Untainted UserEntity createUser(@Tainted UserEntity userEntity) {
        try (var connection = dataSource.getConnection();
             @Untainted Statement statement = connection.createStatement()) {
            // Unsanitized userEntity info
            statement.execute("INSERT INTO \"user\"(login, encoded_password, first_name, last_name) VALUES ('"
                + userEntity.login() + "', '"
                + userEntity.encodedPassword() + "', '"
                + userEntity.firstName() + "', '"
                + userEntity.lastName() + "')"
            );
            // userEntity not modified
            return userEntity;
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Finds and returns queried UserEntity by login (username) string
     * @param @Tainted login: unsanitized username from login attempt
     * @return @Tainted Optional<UserEntity>: returns user to be logged in
     * or null if login invalid
     * @throws TooManyUsersWithTheSameLogin
     */
    @Untainted Optional<UserEntity> findUserByLogin(@Tainted String login) throws TooManyUsersWithTheSameLogin {
        try (var connection = dataSource.getConnection();
             @Untainted Statement statement = connection.createStatement();
             @Tainted ResultSet resultSet = statement.executeQuery("SELECT * FROM \"user\" WHERE login = '" + login + "'")) {
            @Untainted List<UserEntity> users = new ArrayList<>();
            while (resultSet.next()) {
                users.add(mapToEntity(resultSet));
            }
            if (users.size() == 0) {
                return Optional.empty();
            } else if (users.size() > 1) {
                throw new TooManyUsersWithTheSameLogin(login);
            }
            return Optional.of(users.get(0));
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Returns a user from ResultSet results of search query
     * @param @Tainted resultSet: results of search query
     * @return @Tainted UserEntity: result contains potentially dangerous
     * user information
     */
    private @Untainted UserEntity mapToEntity(@Tainted ResultSet resultSet) {
        try {
            return new @Tainted UserEntity(
                resultSet.getString("login"),
                resultSet.getString("encoded_password"),
                resultSet.getString("first_name"),
                resultSet.getString("last_name")
            );
        } catch (SQLException e) {
            throw new RuntimeException("Unable to read information from resultset", e);
        }
    }
}
