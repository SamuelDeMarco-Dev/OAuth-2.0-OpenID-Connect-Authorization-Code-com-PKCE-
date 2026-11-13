package br.unoesc.cyber.client.web;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import br.unoesc.cyber.client.config.OidcClientProperties;
import br.unoesc.cyber.client.session.SessionService;
import br.unoesc.cyber.client.user.UserAccountRepository;

@Controller
class HomeController {

    private final OidcClientProperties props;
    private final UserAccountRepository users;

    HomeController(OidcClientProperties props, UserAccountRepository users) {
        this.props = props;
        this.users = users;
    }

    @GetMapping("/")
    String home(HttpServletRequest request, Model model) {
        model.addAttribute("issuer", props.issuer());
        SessionService.currentUserId(request).flatMap(users::findById)
                .ifPresent(user -> model.addAttribute("user", user));
        return "index";
    }
}
