package com.mjh.adapter.signing.swagger;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SpringdocConfig {
    @Bean
    public OpenAPI springShopOpenAPI() {
        return new OpenAPI()
                .info(new Info().title("Signing Adapter")
                        .description("Signing adapter for HashSigning Service")
                        .version("1.0.1")
                        .contact(new Contact().name("KeySign Team").url("https://keysign.my.id").email("keysign.id@gmail.com"))
                        .license(new License().name("Affero General Public License (AGPL)").url("https://www.gnu.org/licenses/agpl-3.0.en.html")))
//                .externalDocs(new ExternalDocumentation()
//                        .description("Keysign Team")
//                        .url("https://keysign.my.id"))
                ;
    }
}
