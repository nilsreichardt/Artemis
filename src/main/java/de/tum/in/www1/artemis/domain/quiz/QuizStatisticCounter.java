package de.tum.in.www1.artemis.domain.quiz;

import javax.persistence.Column;
import javax.persistence.DiscriminatorColumn;
import javax.persistence.DiscriminatorType;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.Inheritance;
import javax.persistence.InheritanceType;
import javax.persistence.Table;

import org.hibernate.annotations.Cache;
import org.hibernate.annotations.CacheConcurrencyStrategy;

import com.fasterxml.jackson.annotation.JsonInclude;

import de.tum.in.www1.artemis.domain.DomainObject;

/**
 * A QuizStatisticCounter.
 */
@Entity
@Table(name = "quiz_statistic_counter")
@Inheritance(strategy = InheritanceType.SINGLE_TABLE)
@DiscriminatorColumn(name = "discriminator", discriminatorType = DiscriminatorType.STRING)
@DiscriminatorValue(value = "SC")
@Cache(usage = CacheConcurrencyStrategy.NONSTRICT_READ_WRITE)
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public abstract class QuizStatisticCounter extends DomainObject {

    @Column(name = "rated_counter")
    private Integer ratedCounter = 0;

    @Column(name = "un_rated_counter")
    private Integer unRatedCounter = 0;

    public Integer getRatedCounter() {
        return ratedCounter;
    }

    public void setRatedCounter(Integer ratedCounter) {
        this.ratedCounter = ratedCounter;
    }

    public Integer getUnRatedCounter() {
        return unRatedCounter;
    }

    public void setUnRatedCounter(Integer unRatedCounter) {
        this.unRatedCounter = unRatedCounter;
    }
}
