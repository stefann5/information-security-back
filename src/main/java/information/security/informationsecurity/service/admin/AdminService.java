package information.security.informationsecurity.service.admin;

import information.security.informationsecurity.dto.admin.AdminCertificateRequestDTO;
import information.security.informationsecurity.dto.admin.CAUserResponseDTO;
import information.security.informationsecurity.dto.admin.CreateCAUserRequestDTO;
import information.security.informationsecurity.dto.certificate.CertificateRequestDTO;
import information.security.informationsecurity.dto.certificate.CertificateResponseDTO;
import information.security.informationsecurity.model.auth.CAUser;
import information.security.informationsecurity.model.auth.Role;
import information.security.informationsecurity.model.certificate.Certificate;
import information.security.informationsecurity.repository.certificate.CertificateRepository;
import information.security.informationsecurity.repository.user.CARepository;
import information.security.informationsecurity.repository.user.UserRepository;
import information.security.informationsecurity.service.certificate.CertificateService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional
public class AdminService {

    private final CARepository caRepository;
    private final UserRepository userRepository;
    private final CertificateRepository certificateRepository;
    private final CertificateService certificateService;
    private final PasswordEncoder passwordEncoder;

    /**
     * Get all CA users
     */
    public List<CAUserResponseDTO> getAllCAUsers() {
        List<CAUser> caUsers = caRepository.findAll();

        return caUsers.stream()
                .map(this::convertToCAUserResponseDTO)
                .collect(Collectors.toList());
    }

    /**
     * Get CA user by ID
     */
    public CAUserResponseDTO getCAUser(Integer id) {
        CAUser caUser = caRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("CA user not found"));

        return convertToCAUserResponseDTO(caUser);
    }

    /**
     * Create new CA user
     */
    public CAUserResponseDTO createCAUser(CreateCAUserRequestDTO request, String adminUsername) {
        // Check if username already exists
        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            throw new RuntimeException("Username already exists");
        }

        CAUser caUser = new CAUser();
        caUser.setUsername(request.getUsername());
        caUser.setPassword(passwordEncoder.encode(request.getPassword()));
        caUser.setName(request.getName());
        caUser.setSurname(request.getSurname());
        caUser.setOrganization(request.getOrganization());
        caUser.setRole(Role.CA);
        caUser.setAuthorities("CA");
        caUser.setActive(true); // Admin-created users are immediately active

        caUser = caRepository.save(caUser);

        return convertToCAUserResponseDTO(caUser);
    }

    /**
     * Issue CA certificate for a specific CA user
     */
    public CertificateResponseDTO issueCACertificateForUser(AdminCertificateRequestDTO request, String adminUsername) {
        // Get the CA user for whom to issue the certificate
        CAUser caUser = caRepository.findById(request.getCaUserId())
                .orElseThrow(() -> new RuntimeException("CA user not found"));

        // Convert AdminCertificateRequestDTO to CertificateRequestDTO
        CertificateRequestDTO certRequest = convertToCertificateRequestDTO(request);

        // Create certificate using existing certificate service, but assign ownership to CA user
        return certificateService.issueCertificateForUser(certRequest, adminUsername, caUser);
    }

    /**
     * Convert AdminCertificateRequestDTO to CertificateRequestDTO
     */
    private CertificateRequestDTO convertToCertificateRequestDTO(AdminCertificateRequestDTO request) {
        CertificateRequestDTO certRequest = new CertificateRequestDTO();

        certRequest.setCommonName(request.getCommonName());
        certRequest.setOrganizationName(request.getOrganizationName());
        certRequest.setOrganizationalUnit(request.getOrganizationalUnit());
        certRequest.setCountryCode(request.getCountryCode());
        certRequest.setEmailAddress(request.getEmailAddress());
        certRequest.setLocality(request.getLocality());
        certRequest.setState(request.getState());
        certRequest.setSubjectAlternativeNames(request.getSubjectAlternativeNames());
        certRequest.setValidFrom(request.getValidFrom());
        certRequest.setValidTo(request.getValidTo());
        certRequest.setKeyUsage(request.getKeyUsage());
        certRequest.setExtendedKeyUsage(request.getExtendedKeyUsage());
        certRequest.setIsCA(request.getIsCA());
        certRequest.setPathLenConstraint(request.getPathLenConstraint());
        certRequest.setIssuerCertificateId(request.getIssuerCertificateId());
        certRequest.setCertificateType(request.getCertificateType());
        certRequest.setKeySize(request.getKeySize());
        certRequest.setAlgorithm(request.getAlgorithm());

        return certRequest;
    }

    /**
     * Convert CAUser to CAUserResponseDTO
     */
    private CAUserResponseDTO convertToCAUserResponseDTO(CAUser caUser) {
        CAUserResponseDTO dto = new CAUserResponseDTO();

        dto.setId(caUser.getId());
        dto.setUsername(caUser.getUsername());
        dto.setName(caUser.getName());
        dto.setSurname(caUser.getSurname());
        dto.setOrganization(caUser.getOrganization());
        dto.setActive(caUser.isActive());

        // Count certificates owned by this CA user
        List<Certificate> certificates = certificateRepository.findByOwner(caUser);
        dto.setCertificateCount(certificates.size());

        return dto;
    }
}