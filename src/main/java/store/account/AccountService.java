package store.account;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import org.hibernate.exception.ConstraintViolationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder.SecretKeyFactoryAlgorithm;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AccountService {

    private static final String PASSWORD_HASH_PREFIX = "{pbkdf2-sha256-600000}";
    private static final Pbkdf2PasswordEncoder PASSWORD_ENCODER = new Pbkdf2PasswordEncoder(
        "", 16, 600_000, SecretKeyFactoryAlgorithm.PBKDF2WithHmacSHA256
    );
    private static final String UNKNOWN_ACCOUNT_HASH = PASSWORD_ENCODER.encode(UUID.randomUUID().toString());

    @Autowired
    private AccountRepository accountRepository;

    public Account create(Account account) {

        if (null == account.password()) {
            throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST, "Password is empty"
            );            
        }

        final String pass = account.password().trim();
        if (pass.length() < 6) {
            throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST, "Password must be at least 6 characters"
            );
        }

        if (account.email() == null || account.email().trim().isEmpty()) {
            throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST, "Email is empty"
            );
        }

        account.hashPassword(PASSWORD_HASH_PREFIX + PASSWORD_ENCODER.encode(pass));

        try {
            return accountRepository.save(new AccountModel(account)).to();
        } catch (DataIntegrityViolationException e) {
            if (e.getCause() instanceof ConstraintViolationException violation
                    && "accounts_email_key".equals(violation.getConstraintName())) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already registered", e);
            }
            throw e;
        }
    }

    public Account findByEmailAndPassword(String email, String password) {

        if (password == null || password.isEmpty()) {
            throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST, "Password is empty"
            );
        }

        Account account = accountRepository.findByEmail(email).map(AccountModel::to).orElse(null);
        if (account == null) {
            PASSWORD_ENCODER.matches(password, UNKNOWN_ACCOUNT_HASH);
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
        }

        String storedHash = account.hashPassword();
        boolean legacy = !storedHash.startsWith(PASSWORD_HASH_PREFIX);
        boolean valid = legacy
            ? MessageDigest.isEqual(legacyHash(password).getBytes(StandardCharsets.US_ASCII),
                storedHash.getBytes(StandardCharsets.US_ASCII))
            : PASSWORD_ENCODER.matches(password, storedHash.substring(PASSWORD_HASH_PREFIX.length()));
        if (!valid) {
            if (legacy) {
                PASSWORD_ENCODER.matches(password, UNKNOWN_ACCOUNT_HASH);
            }
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
        }

        if (legacy) {
            accountRepository.upgradePasswordHash(
                account.id(), storedHash, PASSWORD_HASH_PREFIX + PASSWORD_ENCODER.encode(password)
            );
        }
        return account;
    }

    public Account findById(String id) {
        return accountRepository.findById(id)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Account not found"))
            .to();
    }

    public void delete(String id) {
        accountRepository.deleteById(id);
    }

    public List<Account> findAll() {
        return accountRepository.findAll().stream()
            .map(AccountModel::to)
            .toList();
    }

    // shortcut: retain legacy verification until remaining SHA-256 passwords are reset.
    private String legacyHash(String text) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(text.getBytes(StandardCharsets.UTF_8));
            byte[] digest = md.digest();
            return Base64.getEncoder().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }
    
}
