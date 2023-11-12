package com.example.TestSpringBootApp.Controller;

import com.example.TestSpringBootApp.Util.Util;
import com.example.TestSpringBootApp.dto.LicenseRequestDto;
import com.example.TestSpringBootApp.dto.LicenseRequestEncryptedDto;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;


import java.util.Base64;

@RestController
@RequestMapping("/test")
public class TestController {

    private String userId = "apiuser2";
    private String password = "3U^LnrnH}R7(REORF%qm";
    private String url = "https://apps.sharearchiver.cloud/SaLicenseApp";
    private String oauthUrl = "/oauth/token";
    private String licenseRequestUrl = "/api/license-request";
    private String clientId = "testjwtclientid";
    private String clientSecret = "XY7kmzoNzl100";
    private String grantType = "password";

    @PostMapping("/requestLicense")
    public String requestLicense() {

        LicenseRequestDto requestDto = LicenseRequestDto.builder()
                .companyName("Yusuf Test2")
                .address("Bangladesh")
                .contactName("Yusuf")
                .contactPhone("01670010682")
                .contactEmail("yusufst000@gmail.com")
                .build();
        boolean productionRequest = true;
        String systemId = null;

        String key = requestDto.getCompanyName() + "|" + (systemId != null ? systemId: "") + "|" + (requestDto.getContactName() != null ? requestDto.getContactName() : "")
                + "|" + (requestDto.getContactEmail() != null ? requestDto.getContactEmail() : "")
                + "|" + (requestDto.getAddress()!= null ? requestDto.getAddress() : "")
                + "|"+ (requestDto.getContactPhone()!= null ? requestDto.getContactPhone() : "")
                + "|" + (productionRequest ? "prod" : "trial");

        String encryptedKey = Util.encrypt(key);
        System.out.println(encryptedKey);
        LicenseRequestEncryptedDto requestEncryptedDto = new LicenseRequestEncryptedDto();
        requestEncryptedDto.setEncryptedKey(encryptedKey);
        WebClient client = WebClient.create();
        String accessToken = getAccessToken(client);
        Mono<String> resource = client.post()
                            .uri(url + licenseRequestUrl)
                            .headers(h -> h.setContentType(MediaType.APPLICATION_JSON))
                            .headers(h -> h.setBearerAuth(accessToken))
                            .bodyValue(requestEncryptedDto)
                            .retrieve()
                            .bodyToMono(String.class);

        System.out.println(resource.block());
        return resource.block();
    }

    private String getAccessToken(WebClient client) {
        String encodedClientData =
                Base64.getEncoder().encodeToString( (clientId + ":" + clientSecret).getBytes());
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", grantType);
        formData.add("username", userId);
        formData.add("password", password);
        Mono<JsonNode> resource = client.post()
                .uri(url + oauthUrl)
                .header("Authorization", "Basic " + encodedClientData)
                .body(BodyInserters.fromFormData(formData))
                .retrieve()
                .bodyToMono(JsonNode.class);
        JsonNode jsonNode = resource.block();
        return jsonNode.get("access_token").textValue();

    }

    @PutMapping("/upload")
    public boolean refreshLicense(@RequestParam("file") MultipartFile uploadfile){
        Util.checkImageFile(uploadfile);
        return true;
    }
}
