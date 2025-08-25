package information.security.informationsecurity.dto.auth.password;

// PasswordStrength.java
public class PasswordStrength {
    private int score; // 0-4
    private String feedback;
    private boolean isAcceptable;

    public PasswordStrength(int score, String feedback, boolean isAcceptable) {
        this.score = score;
        this.feedback = feedback;
        this.isAcceptable = isAcceptable;
    }

    // getters and setters
    public int getScore() { return score; }
    public String getFeedback() { return feedback; }
    public boolean isAcceptable() { return isAcceptable; }
}
