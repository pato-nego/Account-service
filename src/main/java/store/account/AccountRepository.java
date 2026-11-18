package store.account;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.transaction.annotation.Transactional;

public interface AccountRepository extends CrudRepository<AccountModel, String> {

    List<AccountModel> findAll();

    Optional<AccountModel> findByEmail(String email);

    @Transactional
    @Modifying
    @Query("update AccountModel a set a.hashPassword = ?3 where a.id = ?1 and a.hashPassword = ?2")
    void upgradePasswordHash(String id, String currentHash, String upgradedHash);
    
}
