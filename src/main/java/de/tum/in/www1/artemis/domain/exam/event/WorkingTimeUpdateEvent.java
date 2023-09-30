package de.tum.in.www1.artemis.domain.exam.event;

import javax.persistence.Column;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;

import de.tum.in.www1.artemis.web.rest.dto.examevent.WorkingTimeUpdateEventDTO;

/**
 * An event indicating an updated working time for a specific student exam.
 */
@Entity
@DiscriminatorValue(value = "W")
public class WorkingTimeUpdateEvent extends ExamLiveEvent {

    /**
     * The new working time in seconds.
     */
    @Column(name = "newWorkingTime")
    private int newWorkingTime;

    /**
     * The old working time in seconds.
     */
    @Column(name = "oldWorkingTime")
    private int oldWorkingTime;

    /**
     * While the event always contains the working time for a specific student exam,
     * this flags indicates whether the working time was updated for every student exam of the exam.
     */
    @Column(name = "courseWide")
    private boolean courseWide;

    public int getNewWorkingTime() {
        return newWorkingTime;
    }

    public void setNewWorkingTime(int newWorkingTime) {
        this.newWorkingTime = newWorkingTime;
    }

    public int getOldWorkingTime() {
        return oldWorkingTime;
    }

    public void setOldWorkingTime(int oldWorkingTime) {
        this.oldWorkingTime = oldWorkingTime;
    }

    public boolean isCourseWide() {
        return courseWide;
    }

    public void setCourseWide(boolean courseWide) {
        this.courseWide = courseWide;
    }

    @Override
    public WorkingTimeUpdateEventDTO asDTO() {
        var dto = new WorkingTimeUpdateEventDTO();
        super.populateDTO(dto);
        dto.setNewWorkingTime(newWorkingTime);
        dto.setOldWorkingTime(oldWorkingTime);
        dto.setCourseWide(courseWide);
        return dto;
    }
}
