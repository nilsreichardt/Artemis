package de.tum.in.www1.artemis.domain.plagiarism;

import java.util.*;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.OneToOne;
import javax.persistence.Table;

import org.hibernate.annotations.Cache;
import org.hibernate.annotations.CacheConcurrencyStrategy;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

import de.tum.in.www1.artemis.domain.DomainObject;
import de.tum.in.www1.artemis.domain.Exercise;

/**
 * Stores configuration for manual and continuous plagiarism control.
 */
@Entity
@Table(name = "plagiarism_detection_config")
@Cache(usage = CacheConcurrencyStrategy.NONSTRICT_READ_WRITE)
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class PlagiarismDetectionConfig extends DomainObject {

    @OneToOne(mappedBy = "plagiarismDetectionConfig", fetch = FetchType.LAZY)
    @JsonIgnoreProperties("plagiarismDetectionConfig")
    private Exercise exercise;

    @Column(name = "continuous_plagiarism_control_enabled")
    private boolean continuousPlagiarismControlEnabled = false;

    @Column(name = "continuous_plagiarism_control_post_due_date_checks_enabled")
    private boolean continuousPlagiarismControlPostDueDateChecksEnabled = false;

    @Column(name = "similarity_threshold")
    private float similarityThreshold;

    @Column(name = "minimum_score")
    private int minimumScore;

    @Column(name = "minimum_size")
    private int minimumSize;

    public Exercise getExercise() {
        return exercise;
    }

    public void setExercise(Exercise exercise) {
        this.exercise = exercise;
    }

    public boolean isContinuousPlagiarismControlEnabled() {
        return continuousPlagiarismControlEnabled;
    }

    public void setContinuousPlagiarismControlEnabled(boolean continuousPlagiarismControlEnabled) {
        this.continuousPlagiarismControlEnabled = continuousPlagiarismControlEnabled;
    }

    public boolean isContinuousPlagiarismControlPostDueDateChecksEnabled() {
        return continuousPlagiarismControlPostDueDateChecksEnabled;
    }

    public void setContinuousPlagiarismControlPostDueDateChecksEnabled(boolean continuousPlagiarismControlPostDueDateChecksEnabled) {
        this.continuousPlagiarismControlPostDueDateChecksEnabled = continuousPlagiarismControlPostDueDateChecksEnabled;
    }

    public float getSimilarityThreshold() {
        return similarityThreshold;
    }

    public int getMinimumScore() {
        return minimumScore;
    }

    public int getMinimumSize() {
        return minimumSize;
    }

    public void setSimilarityThreshold(float similarityThreshold) {
        this.similarityThreshold = similarityThreshold;
    }

    public void setMinimumScore(int minimumScore) {
        this.minimumScore = minimumScore;
    }

    public void setMinimumSize(int minimumSize) {
        this.minimumSize = minimumSize;
    }

    /**
     * Creates PlagiarismDetectionConfig with default data
     *
     * @return PlagiarismDetectionConfig with default values
     */
    public static PlagiarismDetectionConfig createDefault() {
        var config = new PlagiarismDetectionConfig();
        config.setContinuousPlagiarismControlEnabled(false);
        config.setContinuousPlagiarismControlPostDueDateChecksEnabled(false);
        config.setSimilarityThreshold(0.9f);
        config.setMinimumScore(0);
        config.setMinimumSize(50);
        return config;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        if (!super.equals(o))
            return false;
        PlagiarismDetectionConfig that = (PlagiarismDetectionConfig) o;
        return continuousPlagiarismControlEnabled == that.continuousPlagiarismControlEnabled
                && continuousPlagiarismControlPostDueDateChecksEnabled == that.continuousPlagiarismControlPostDueDateChecksEnabled
                && Float.compare(similarityThreshold, that.similarityThreshold) == 0 && minimumScore == that.minimumScore && minimumSize == that.minimumSize
                && Objects.equals(exercise, that.exercise);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), exercise, continuousPlagiarismControlEnabled, continuousPlagiarismControlPostDueDateChecksEnabled, similarityThreshold, minimumScore,
                minimumSize);
    }

    @Override
    public String toString() {
        return "PlagiarismDetectionConfig{" + "exercise=" + exercise + ", continuousPlagiarismControlEnabled=" + continuousPlagiarismControlEnabled
                + ", continuousPlagiarismControlPostDueDateChecksEnabled=" + continuousPlagiarismControlPostDueDateChecksEnabled + ", similarityThreshold=" + similarityThreshold
                + ", minimumScore=" + minimumScore + ", minimumSize=" + minimumSize + '}';
    }
}
