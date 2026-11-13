package br.unoesc.cyber.client.session;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * A cada requisição: valida a sessão local no servidor e publica o id do usuário em
 * {@link SessionService#CURRENT_USER_ID}. Cookie inválido/expirado é apagado do navegador.
 * A autorização por role (issue #22) deve ler o usuário a partir daqui, nunca do HTML.
 */
@Component
class SessionFilter extends OncePerRequestFilter {

    private final SessionService sessions;

    SessionFilter(SessionService sessions) {
        this.sessions = sessions;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        sessions.resolve(request).ifPresentOrElse(
                userId -> request.setAttribute(SessionService.CURRENT_USER_ID, userId),
                () -> {
                    if (sessions.hasCookie(request)) {
                        sessions.clearCookie(response);
                    }
                });
        chain.doFilter(request, response);
    }
}
