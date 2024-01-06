package de.tum.in.www1.artemis.domain.plagiarism;

import javax.persistence.DiscriminatorColumn;
import javax.persistence.DiscriminatorType;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.Inheritance;
import javax.persistence.InheritanceType;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

import de.tum.in.www1.artemis.domain.DomainObject;

@Entity
@Inheritance(strategy = InheritanceType.SINGLE_TABLE)
@DiscriminatorColumn(name = "discriminator", discriminatorType = DiscriminatorType.STRING)
@DiscriminatorValue("PSE")
@Table(name = "plagiarism_submission_element")
public class PlagiarismSubmissionElement extends DomainObject {

    @ManyToOne
    private PlagiarismSubmission<?> plagiarismSubmission;

    public PlagiarismSubmission<?> getPlagiarismSubmission() {
        return plagiarismSubmission;
    }

    public void setPlagiarismSubmission(PlagiarismSubmission<?> plagiarismSubmission) {
        this.plagiarismSubmission = plagiarismSubmission;
    }
}
