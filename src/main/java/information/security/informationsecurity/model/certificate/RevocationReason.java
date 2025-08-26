package information.security.informationsecurity.model.certificate;

public enum RevocationReason {
    UNSPECIFIED,
    KEY_COMPROMISE,
    CA_COMPROMISE,
    AFFILIATION_CHANGED,
    SUPERSEDED,
    CESSATION_OF_OPERATION,
    CERTIFICATE_HOLD,
    PRIVILEGE_WITHDRAWN,
    AA_COMPROMISE
}