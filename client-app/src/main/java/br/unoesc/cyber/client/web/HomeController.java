package br.unoesc.cyber.client.web;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import br.unoesc.cyber.client.config.OidcClientProperties;

@Controller
class HomeController {

    private final OidcClientProperties props;

    HomeController(OidcClientProperties props) {
        this.props = props;
    }

    @GetMapping("/")
    String home(Model model) {
        model.addAttribute("issuer", props.issuer());
        return "index";
    }
}
