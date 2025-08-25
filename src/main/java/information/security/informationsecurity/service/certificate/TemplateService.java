package information.security.informationsecurity.service.certificate;

import information.security.informationsecurity.dto.certificate.TemplateRequestDTO;
import information.security.informationsecurity.dto.certificate.TemplateResponseDTO;
import information.security.informationsecurity.model.certificate.Template;
import information.security.informationsecurity.model.certificate.Certificate;
import information.security.informationsecurity.model.auth.User;
import information.security.informationsecurity.repository.certificate.TemplateRepository;
import information.security.informationsecurity.repository.certificate.CertificateRepository;
import information.security.informationsecurity.repository.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional
public class TemplateService {

    private final TemplateRepository templateRepository;
    private final CertificateRepository certificateRepository;
    private final UserRepository userRepository;
    private final ValidationService validationService;

    public TemplateResponseDTO createTemplate(TemplateRequestDTO request, String currentUsername) {
        User currentUser = userRepository.findByUsername(currentUsername)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Validate template name uniqueness
        if (templateRepository.existsByTemplateName(request.getTemplateName())) {
            throw new RuntimeException("Template with this name already exists");
        }

        // Get CA issuer certificate
        Certificate caIssuer = certificateRepository.findById(request.getCaIssuerId())
                .orElseThrow(() -> new RuntimeException("CA issuer certificate not found"));

        // Validate CA access
        validationService.validateCACertificateAccess(caIssuer, currentUser);

        // Create template
        Template template = new Template();
        template.setTemplateName(request.getTemplateName());
        template.setCaIssuer(caIssuer);
        template.setCommonNameRegex(request.getCommonNameRegex());
        template.setSanRegex(request.getSanRegex());
        template.setMaxTtlDays(request.getMaxTtlDays());
        template.setDefaultKeyUsage(request.getDefaultKeyUsage());
        template.setDefaultExtendedKeyUsage(request.getDefaultExtendedKeyUsage());
        template.setCreatedBy(currentUser);

        template = templateRepository.save(template);

        return convertToResponseDTO(template);
    }

    public List<TemplateResponseDTO> getAvailableTemplates(String currentUsername) {
        User currentUser = userRepository.findByUsername(currentUsername)
                .orElseThrow(() -> new RuntimeException("User not found"));

        List<Template> templates;

        if (currentUser.getAuthorities().contains("ADMIN")) {
            templates = templateRepository.findAll();
        } else {
            templates = templateRepository.findAvailableTemplatesForUser(currentUser);
        }

        return templates.stream()
                .map(this::convertToResponseDTO)
                .collect(Collectors.toList());
    }

    public TemplateResponseDTO getTemplate(Long templateId, String currentUsername) {
        User currentUser = userRepository.findByUsername(currentUsername)
                .orElseThrow(() -> new RuntimeException("User not found"));

        Template template = templateRepository.findById(templateId)
                .orElseThrow(() -> new RuntimeException("Template not found"));

        // Validate access
        if (!currentUser.getAuthorities().contains("ADMIN") &&
                !(template.getCreatedBy().getId()==(currentUser.getId())) &&
                !(template.getCaIssuer().getOwner().getId()==(currentUser.getId()))) {
            throw new RuntimeException("You don't have access to this template");
        }

        return convertToResponseDTO(template);
    }

    private TemplateResponseDTO convertToResponseDTO(Template template) {
        TemplateResponseDTO dto = new TemplateResponseDTO();
        dto.setId(template.getId());
        dto.setTemplateName(template.getTemplateName());
        dto.setCaIssuerName(template.getCaIssuer().getSubjectDN());
        dto.setCommonNameRegex(template.getCommonNameRegex());
        dto.setSanRegex(template.getSanRegex());
        dto.setMaxTtlDays(template.getMaxTtlDays());
        dto.setDefaultKeyUsage(template.getDefaultKeyUsage());
        dto.setDefaultExtendedKeyUsage(template.getDefaultExtendedKeyUsage());
        dto.setCreatedBy(template.getCreatedBy().getUsername());
        dto.setCreatedAt(template.getCreatedAt());

        return dto;
    }
}