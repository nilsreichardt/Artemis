package de.tum.in.www1.artemis.domain.iris.message;

import java.util.List;
import java.util.Optional;

import javax.persistence.*;

import com.fasterxml.jackson.annotation.JsonIdentityInfo;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.ObjectIdGenerators;

/**
 * An IrisExercisePlanMessageContent represents an Iris-generated plan to make changes to an exercise.
 * The plans may or may not have been edited by the user before execution.
 */
@Entity
@Table(name = "iris_exercise_plan_message_content")
@DiscriminatorValue(value = "EXERCISE_PLAN")
@JsonInclude(JsonInclude.Include.NON_EMPTY)
@JsonIdentityInfo(generator = ObjectIdGenerators.PropertyGenerator.class, property = "id", scope = IrisExercisePlan.class)
public class IrisExercisePlan extends IrisMessageContent {

    @OrderColumn(name = "exercise_plan_step_order")
    @OneToMany(mappedBy = "plan", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.EAGER)
    private List<IrisExercisePlanStep> steps;

    public List<IrisExercisePlanStep> getSteps() {
        return steps;
    }

    /**
     * Sets the steps of this plan.
     * This method will ensure that the bidirectional relationship between the plan and its steps is consistent.
     *
     * @param steps the steps of this plan
     */
    public void setSteps(List<IrisExercisePlanStep> steps) {
        if (this.steps != null) {
            this.steps.forEach(step -> step.setPlan(null));
        }
        this.steps = steps;
        if (this.steps != null) {
            this.steps.forEach(step -> step.setPlan(this));
        }
    }

    /**
     * Gets the next step in the plan.
     * The next step is the step following the last completed step.
     * If the plan is empty or all steps have been completed, an empty optional is returned.
     *
     * @return the next step in the plan
     */
    public Optional<IrisExercisePlanStep> getNextStep() {
        var nextStepIndex = getNextStepIndex();
        if (nextStepIndex < steps.size()) {
            return Optional.of(steps.get(nextStepIndex));
        }
        return Optional.empty();
    }

    /**
     * Gets the index of next step
     */
    private int getNextStepIndex() {
        for (int i = steps.size() - 1; i >= 0; i--) {
            var step = steps.get(i);
            if (step.getExecutionStage() == IrisExercisePlanStep.ExecutionStage.COMPLETE) {
                return i + 1;
            }
        }
        return 0;
    }

    @Override
    public String getContentAsString() {
        var sb = new StringBuilder("Exercise Plan:\n");
        for (var step : steps) {
            sb.append(step.getComponent()).append(": \"").append(step.getInstructions()).append("\" - ").append(step.getExecutionStage()).append("\n");
        }
        return sb.toString();
    }

    @Override
    public String toString() {
        return "IrisExercisePlan{" + "message=" + (message == null ? "null" : message.getId()) + ", steps=" + steps + '}';
    }

}
