package de.tum.in.www1.artemis.domain.exam.event;

import java.time.Instant;

import javax.persistence.Column;
import javax.persistence.DiscriminatorColumn;
import javax.persistence.DiscriminatorType;
import javax.persistence.Entity;
import javax.persistence.EntityListeners;
import javax.persistence.Inheritance;
import javax.persistence.InheritanceType;
import javax.persistence.Table;

import org.hibernate.annotations.Cache;
import org.hibernate.annotations.CacheConcurrencyStrategy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import de.tum.in.www1.artemis.domain.DomainObject;
import de.tum.in.www1.artemis.service.exam.ExamLiveEventsService;
import de.tum.in.www1.artemis.web.rest.dto.examevent.ExamLiveEventDTO;

/**
 * Base class for all exam live events. An exam live event indicates that an event or change has occurred during an exam.
 * See the subclasses for more details.
 *
 * @see WorkingTimeUpdateEvent
 * @see ExamWideAnnouncementEvent
 * @see ExamLiveEventsService
 */
@Entity
@Table(name = "exam_live_event")
@Cache(usage = CacheConcurrencyStrategy.NONSTRICT_READ_WRITE)
@Inheritance(strategy = InheritanceType.SINGLE_TABLE)
@DiscriminatorColumn(name = "discriminator", discriminatorType = DiscriminatorType.STRING)
@EntityListeners(AuditingEntityListener.class)
public abstract class ExamLiveEvent extends DomainObject {

    @Column(name = "created_by", nullable = false, length = 50, updatable = false)
    private String createdBy;

    @CreatedDate
    @Column(name = "created_date", updatable = false)
    private Instant createdDate = Instant.now();

    @Column(name = "exam_id", nullable = false, updatable = false)
    private Long examId;

    @Column(name = "student_exam_id", updatable = false)
    private Long studentExamId;

    public String getCreatedBy() {
        return createdBy;
    }

    public void setCreatedBy(String createdBy) {
        this.createdBy = createdBy;
    }

    public Instant getCreatedDate() {
        return createdDate;
    }

    public void setCreatedDate(Instant createdDate) {
        this.createdDate = createdDate;
    }

    public Long getExamId() {
        return examId;
    }

    public void setExamId(Long examId) {
        this.examId = examId;
    }

    public Long getStudentExamId() {
        return studentExamId;
    }

    public void setStudentExamId(Long studentExamId) {
        this.studentExamId = studentExamId;
    }

    protected void populateDTO(ExamLiveEventDTO dto) {
        dto.setId(getId());
        dto.setCreatedBy(getCreatedBy());
        dto.setCreatedDate(getCreatedDate());
    }

    public abstract ExamLiveEventDTO asDTO();
}
