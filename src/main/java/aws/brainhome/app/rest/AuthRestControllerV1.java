package aws.brainhome.app.rest;


import aws.brainhome.app.dto.AuthRequestDto;
import aws.brainhome.app.dto.AuthResponseDto;
import aws.brainhome.app.dto.UserDto;
import aws.brainhome.app.entity.UserEntity;
import aws.brainhome.app.mapper.UserMapper;
import aws.brainhome.app.security.CustomPrincipal;
import aws.brainhome.app.security.SecurityService;
import aws.brainhome.app.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthRestControllerV1 {
    private final SecurityService securityService;
    private final UserService userService;
    private final UserMapper userMapper;

    @PostMapping("/register")
    public Mono<UserDto> register(@RequestBody UserDto user) {
        UserEntity userEntity = userMapper.map(user);
        return userService.registerUser(userEntity)
                .map(userMapper::map);
    }

    @PostMapping("/login")
    public Mono<AuthResponseDto> login(@RequestBody AuthRequestDto dto) {
        return securityService.authenticate(dto.getUsername(), dto.getPassword())
                .flatMap(tokenDetails ->
                        Mono.just(AuthResponseDto.builder()
                                .userId(tokenDetails.getUserId())
                                .token(tokenDetails.getToken())
                                .issuedAt(tokenDetails.getIssuedAt())
                                .expiresAt(tokenDetails.getExpiresAt())
                                .build()));
    }

    @GetMapping("/info")
    public Mono<UserDto> getUser(Authentication authentication) {
        CustomPrincipal principal = (CustomPrincipal) authentication.getPrincipal();

        return userService.getUserById(principal.getId())
                .map(userMapper::map);
    }
}
