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
     * @param  userEntity: unsanitized user created by client,
     * with unsanitized login/password/name
     * @return  UserEntity: same userEntity as passed in, not modified
     */
     UserEntity createUser( UserEntity userEntity) {
        try (var connection = dataSource.getConnection();
              Statement statement = connection.createStatement()) {
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
     * @param  login: unsanitized username from login attempt
     * @return  Optional<UserEntity>: returns user to be logged in
     * or null if login invalid
     * @throws TooManyUsersWithTheSameLogin
     */
     Optional<UserEntity> findUserByLogin( String login) throws TooManyUsersWithTheSameLogin {
        try (var connection = dataSource.getConnection();
              Statement statement = connection.createStatement();
              ResultSet resultSet = statement.executeQuery("SELECT * FROM \"user\" WHERE login = '" + login + "'")) {
             List<UserEntity> users = new ArrayList<>();
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
     * @param  resultSet: results of search query
     * @return  UserEntity: result contains potentially dangerous
     * user information
     */
    private  UserEntity mapToEntity( ResultSet resultSet) {
        try {
            return new  UserEntity(
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
