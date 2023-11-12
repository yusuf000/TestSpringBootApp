package com.example.TestSpringBootApp.dto;

import lombok.*;

import jakarta.validation.constraints.NotNull;

/**
 * subho
 */
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@ToString
public class LicenseRequestDto {
    @NotNull
    private String companyName;
    @NotNull
    private String address;
    @NotNull
    private String contactName;
    @NotNull
    private String contactEmail;
    @NotNull
    private String contactPhone;
}
