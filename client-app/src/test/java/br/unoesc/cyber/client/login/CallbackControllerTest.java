package br.unoesc.cyber.client.login;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import br.unoesc.cyber.client.support.AbstractIntegrationTest;
import br.unoesc.cyber.client.token.IdTokenValidationException;
import br.unoesc.cyber.client.token.IdTokenValidator;
import br.unoesc.cyber.client.token.TokenClient;
import br.unoesc.cyber.client.token.TokenExchangeException;
import br.unoesc.cyber.client.token.TokenSet;
import br.unoesc.cyber.client.token.ValidatedIdToken;

class CallbackControllerTest extends AbstractIntegrationTest {

    @Autowired
    MockMvc mvc;
    @MockitoBean
    TokenClient tokenClient;
    @MockitoBean
    IdTokenValidator validator;

    static MockHttpSession preLogin() {
        MockHttpSession session = new MockHttpSession();
        session.setAttribute(PreLoginState.SESSION_KEY, new PreLoginState("state-ok", "nonce-ok", "verifier-ok"));
        return session;
    }

    static void noSession(MvcResult r) {
        String cookies = String.join(";", r.getResponse().getHeaders(HttpHeaders.SET_COOKIE));
        assertThat(cookies).doesNotContain("APP_SID=");
    }

    /** Teste negativo #8 (state divergente). */
    @Test
    void negativo08a_stateDivergente_abortaAntesDaTroca() throws Exception {
        MockHttpSession session = preLogin();
        MvcResult r = mvc.perform(get("/callback").session(session).param("code", "c").param("state", "state-forjado"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString(CallbackController.GENERIC_FAILURE)))
                .andReturn();
        verifyNoInteractions(tokenClient, validator);
        noSession(r);
        assertThat(session.getAttribute(PreLoginState.SESSION_KEY)).as("state de uso único").isNull();
    }

    /** Teste negativo #8 (state ausente). */
    @Test
    void negativo08b_stateAusente_abortaAntesDaTroca() throws Exception {
        noSession(mvc.perform(get("/callback").session(preLogin()).param("code", "c"))
                .andExpect(status().isBadRequest()).andReturn());
        verifyNoInteractions(tokenClient, validator);
    }

    @Test
    void callbackSemLoginEmAndamentoAborta() throws Exception {
        mvc.perform(get("/callback").param("code", "c").param("state", "x")).andExpect(status().isBadRequest());
        verifyNoInteractions(tokenClient, validator);
    }

    @Test
    void erroDoProvedorMostraMensagemAmigavelSemSessao() throws Exception {
        noSession(mvc.perform(get("/callback").session(preLogin()).param("error", "access_denied")
                .param("error_description", "<script>detalhe interno</script>").param("state", "state-ok"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString(CallbackController.DENIED)))
                .andExpect(content().string(org.hamcrest.Matchers.not(containsString("detalhe interno"))))
                .andReturn());
        verifyNoInteractions(tokenClient, validator);
    }

    @Test
    void sucessoTrocaValidaVinculaECriaSessao() throws Exception {
        String sub = UUID.randomUUID().toString();
        when(tokenClient.exchange("c0de", "verifier-ok")).thenReturn(new TokenSet("at", "idt", "rt", 900));
        when(validator.validate("idt", "nonce-ok")).thenReturn(new ValidatedIdToken("https://as.test.example", sub,
                "Ana Admin", sub + "@x.com", true, "admin", List.of()));

        MvcResult r = mvc.perform(get("/callback").session(preLogin()).param("code", "c0de").param("state", "state-ok"))
                .andExpect(redirectedUrl("/")).andReturn();

        verify(validator).validate(eq("idt"), eq("nonce-ok"));
        String cookies = String.join(";", r.getResponse().getHeaders(HttpHeaders.SET_COOKIE));
        assertThat(cookies).contains("APP_SID=").contains("HttpOnly").contains("Secure").contains("SameSite=Lax");
        assertThat(r.getResponse().getContentAsString()).doesNotContain("idt").doesNotContain("\"at\"");
    }

    @Test
    void idTokenRejeitadoNaoCriaSessao() throws Exception {
        when(tokenClient.exchange(anyString(), anyString())).thenReturn(new TokenSet("at", "idt", null, 900));
        when(validator.validate(anyString(), any())).thenThrow(new IdTokenValidationException(8, "nonce diferente"));
        noSession(mvc.perform(get("/callback").session(preLogin()).param("code", "c").param("state", "state-ok"))
                .andExpect(status().isBadRequest()).andReturn());
    }

    @Test
    void falhaNaTrocaNaoCriaSessaoNemValida() throws Exception {
        when(tokenClient.exchange(anyString(), anyString())).thenThrow(new TokenExchangeException("timeout"));
        noSession(mvc.perform(get("/callback").session(preLogin()).param("code", "c").param("state", "state-ok"))
                .andExpect(status().isBadRequest()).andReturn());
        verifyNoInteractions(validator);
    }
}
