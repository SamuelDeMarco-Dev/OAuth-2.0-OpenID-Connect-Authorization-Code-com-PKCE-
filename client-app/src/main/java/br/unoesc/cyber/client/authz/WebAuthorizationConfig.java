package br.unoesc.cyber.client.authz;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/** Rotas protegidas: qualquer usuário autenticado em /perfil; só admin em /admin/**. */
@Configuration
class WebAuthorizationConfig implements WebMvcConfigurer {

    private final AuthorizationInterceptor interceptor;

    WebAuthorizationConfig(AuthorizationInterceptor interceptor) {
        this.interceptor = interceptor;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(interceptor).addPathPatterns("/perfil", "/admin", "/admin/**");
    }
}
