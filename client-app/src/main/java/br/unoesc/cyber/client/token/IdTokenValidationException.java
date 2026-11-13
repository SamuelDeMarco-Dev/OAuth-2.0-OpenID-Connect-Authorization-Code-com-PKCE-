package br.unoesc.cyber.client.token;

/** ID Token rejeitado. {@code checklistItem} = linha do checklist §4.3 do PDF que falhou. */
public class IdTokenValidationException extends RuntimeException {

    private final int checklistItem;

    public IdTokenValidationException(int checklistItem, String reason) {
        super("Checklist 4.3 #" + checklistItem + ": " + reason);
        this.checklistItem = checklistItem;
    }

    public int checklistItem() {
        return checklistItem;
    }
}
