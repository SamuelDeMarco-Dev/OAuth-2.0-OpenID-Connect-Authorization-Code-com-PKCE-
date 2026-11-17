package br.unoesc.cyber.client.login;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.util.UriComponentsBuilder;

import br.unoesc.cyber.client.crypto.Hashes;
import br.unoesc.cyber.client.discovery.ProviderMetadataService;
import br.unoesc.cyber.client.discovery.ProviderUnavailableException;
import br.unoesc.cyber.client.support.AbstractIntegrationTest;
import br.unoesc.cyber.client.support.TestProperties;
import br.unoesc.cyber.client.support.TestTokens;

class LoginStartControllerTest extends AbstractIntegrationTest {

    @Autowired
    MockMvc mvc;
    @MockitoBean
    ProviderMetadataService metadata;

    @BeforeEach
    void setUp() {
        when(metadata.get()).thenReturn(TestTokens.metadata().get());
    }

    static String param(String url, String name) {
        String raw = UriComponentsBuilder.fromUriString(url).build(true).getQueryParams().getFirst(name);
        return raw == null ? null : URLDecoder.decode(raw, StandardCharsets.UTF_8);
    }

    @Test
    void redirecionaParaOProvedorComPkceStateENonce() throws Exception {
        MockHttpSession session = new MockHttpSession();
        String url = mvc.perform(get("/login").session(session)).andExpect(status().isFound())
                .andReturn().getResponse().getRedirectedUrl();
        PreLoginState pre = (PreLoginState) session.getAttribute(PreLoginState.SESSION_KEY);

        assertThat(url).startsWith(TestProperties.ISSUER + "/authorize?");
        assertThat(param(url, "response_type")).isEqualTo("code");
        assertThat(param(url, "client_id")).isEqualTo(TestProperties.CLIENT_ID);
        assertThat(param(url, "redirect_uri")).isEqualTo(TestProperties.REDIRECT_URI);
        assertThat(param(url, "scope")).isEqualTo("openid profile email");
        assertThat(param(url, "state")).isEqualTo(pre.state()).hasSizeGreaterThanOrEqualTo(22); // >= 128 bits
        assertThat(param(url, "nonce")).isEqualTo(pre.nonce()).hasSizeGreaterThanOrEqualTo(22);
        assertThat(param(url, "code_challenge_method")).isEqualTo("S256");
        assertThat(param(url, "code_challenge")).isEqualTo(Hashes.s256(pre.codeVerifier()));
        assertThat(url).doesNotContain(pre.codeVerifier()).as("o verifier nunca sai do servidor");
    }

    @Test
    void cadaCliqueGeraValoresNovos() throws Exception {
        String a = mvc.perform(get("/login")).andReturn().getResponse().getRedirectedUrl();
        String b = mvc.perform(get("/login")).andReturn().getResponse().getRedirectedUrl();
        assertThat(param(a, "state")).isNotEqualTo(param(b, "state"));
        assertThat(param(a, "nonce")).isNotEqualTo(param(b, "nonce"));
        assertThat(param(a, "code_challenge")).isNotEqualTo(param(b, "code_challenge"));
    }

    @Test
    void provedorForaDoArMostraMensagemAmigavel() throws Exception {
        when(metadata.get()).thenThrow(new ProviderUnavailableException("fora do ar"));
        mvc.perform(get("/login")).andExpect(status().isServiceUnavailable());
    }
}
