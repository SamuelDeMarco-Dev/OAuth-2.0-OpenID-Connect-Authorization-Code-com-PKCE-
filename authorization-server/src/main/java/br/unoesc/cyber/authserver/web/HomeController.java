package br.unoesc.cyber.authserver.web;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import br.unoesc.cyber.authserver.config.AuthServerProperties;

@Controller
class HomeController {

    private final AuthServerProperties props;

    HomeController(AuthServerProperties props) {
        this.props = props;
    }

    @GetMapping("/")
    String home(Model model) {
        model.addAttribute("issuer", props.issuer());
        return "index";
    }
}
