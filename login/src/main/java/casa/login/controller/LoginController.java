package casa.login.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {

    @GetMapping("/public")
    public String publicEndpoint() {
        return "Questo endpoint è pubblico, non serve login!";
    }

    @GetMapping("/private")
    public String privateEndpoint() {
        return "Se vedi questo, sei autenticato ✅";
    }
}
