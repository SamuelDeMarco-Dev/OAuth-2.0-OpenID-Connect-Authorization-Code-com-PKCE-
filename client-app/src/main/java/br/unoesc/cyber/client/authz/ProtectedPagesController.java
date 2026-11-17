package br.unoesc.cyber.client.authz;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestAttribute;

import br.unoesc.cyber.client.user.UserAccount;
import br.unoesc.cyber.client.user.UserAccountRepository;

/** Páginas protegidas. Só são alcançadas depois do {@link AuthorizationInterceptor}. */
@Controller
class ProtectedPagesController {

    private final UserAccountRepository users;

    ProtectedPagesController(UserAccountRepository users) {
        this.users = users;
    }

    @GetMapping("/perfil")
    String profile(@RequestAttribute(AuthorizationInterceptor.CURRENT_USER) UserAccount user, Model model) {
        model.addAttribute("user", user);
        return "perfil";
    }

    @GetMapping("/admin")
    String admin(@RequestAttribute(AuthorizationInterceptor.CURRENT_USER) UserAccount user, Model model) {
        model.addAttribute("user", user);
        model.addAttribute("users", users.findAll());
        return "admin";
    }
}
