package aws.brainhome.app.repository;

import aws.brainhome.app.entity.UserEntity;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import reactor.core.publisher.Mono;

public interface UserRepository extends R2dbcRepository<UserEntity,Long> {

    Mono<UserEntity> findByUsername(String username);
}
