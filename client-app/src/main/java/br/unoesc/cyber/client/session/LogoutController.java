package br.unoesc.cyber.client.session;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;

/** POST /logout. Protegido contra CSRF pelo SameSite=Lax (o cookie não vai em POST vindo de outro site). */
@Controller
class LogoutController {

    private final SessionService sessions;

    LogoutController(SessionService sessions) {
        this.sessions = sessions;
    }

    @PostMapping("/logout")
    String logout(HttpServletRequest request, HttpServletResponse response) {
        sessions.end(request, response);
        return "redirect:/";
    }
}
