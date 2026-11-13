package br.unoesc.cyber.client.config;

import java.io.InputStream;
import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClient;

/**
 * Cliente HTTP do canal de retaguarda (back-channel) com o provedor: TLS validado contra o
 * truststore do projeto (nunca "trust all"), timeouts curtos e sem seguir redirects.
 */
@Configuration
class HttpClientConfig {

    private static final Logger log = LoggerFactory.getLogger(HttpClientConfig.class);

    @Bean
    RestClient oidcRestClient(OidcClientProperties props) {
        HttpClient http = HttpClient.newBuilder()
                .connectTimeout(props.httpTimeout())
                .followRedirects(HttpClient.Redirect.NEVER)
                .sslContext(sslContext(props))
                .build();
        JdkClientHttpRequestFactory factory = new JdkClientHttpRequestFactory(http);
        factory.setReadTimeout(props.httpTimeout());
        return RestClient.builder().requestFactory(factory).build();
    }

    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    SecureRandom secureRandom() {
        return new SecureRandom();
    }

    /** Truststore do projeto se existir; senão, os CAs padrão da JVM (ex.: provedor com certificado público). */
    static SSLContext sslContext(OidcClientProperties props) {
        try {
            String path = props.truststorePath();
            if (!StringUtils.hasText(path) || !Files.exists(Path.of(path))) {
                log.info("Truststore '{}' não encontrado: usando os CAs padrão da JVM", path);
                return SSLContext.getDefault();
            }
            KeyStore trust = KeyStore.getInstance("PKCS12");
            try (InputStream in = Files.newInputStream(Path.of(path))) {
                char[] pass = props.truststorePassword() == null ? null : props.truststorePassword().toCharArray();
                trust.load(in, pass);
            }
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trust);
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, tmf.getTrustManagers(), null);
            log.info("Truststore carregado de {}", path);
            return ctx;
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        } catch (Exception e) {
            throw new IllegalStateException("Falha ao carregar o truststore (rode scripts/gen-dev-secrets.sh)", e);
        }
    }
}
