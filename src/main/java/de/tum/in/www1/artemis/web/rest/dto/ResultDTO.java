package de.tum.in.www1.artemis.web.rest.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import de.tum.in.www1.artemis.domain.Feedback;
import de.tum.in.www1.artemis.domain.ProgrammingExerciseTestCase;
import de.tum.in.www1.artemis.domain.Result;
import de.tum.in.www1.artemis.domain.enumeration.AssessmentType;
import de.tum.in.www1.artemis.domain.enumeration.FeedbackType;
import de.tum.in.www1.artemis.domain.enumeration.Visibility;
import org.hibernate.Hibernate;

import java.time.ZonedDateTime;
import java.util.List;

/**
 * DTO containing {@link Result} information.
 * This does not include large reference attributes in order to send minimal data to the client.
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public record ResultDTO(Long id, ZonedDateTime completionDate, Boolean successful, Double score, Boolean rated,
                        SubmissionDTO submission, ParticipationDTO participation,
                        List<FeedbackDTO> feedbacks, AssessmentType assessmentType, Boolean hasComplaint,
                        Boolean exampleResult, Integer testCaseCount, Integer passedTestCaseCount,
                        Integer codeIssueCount) {

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public record FeedbackDTO(Long id, String text, String detailText, boolean hasLongFeedbackText, String reference,
                              Double credits, Boolean positive, FeedbackType type,
                              Visibility visibility, TestCaseDTO testCase) {

        public static FeedbackDTO of(Feedback feedback) {
            return new FeedbackDTO(feedback.getId(), feedback.getText(), feedback.getDetailText(), feedback.getHasLongFeedbackText(), feedback.getReference(),
                    feedback.getCredits(), feedback.isPositive(), feedback.getType(), feedback.getVisibility(), TestCaseDTO.of(feedback.getTestCase()));

        }
    }

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    public record TestCaseDTO(String testName, Long id) {

        public static TestCaseDTO of(ProgrammingExerciseTestCase testCase) {
            if (testCase == null) {
                return null;
            }
            return new TestCaseDTO(testCase.getTestName(), testCase.getId());
        }
    }

    public static ResultDTO of(Result result) {
        return of(result, result.getFeedbacks());
    }

    /**
     * Converts a Result into a ResultDTO
     *
     * @param result           to convert
     * @param filteredFeedback feedback that should get send to the client, will get converted into {@link FeedbackDTO} objects.
     * @return the converted DTO
     */
    public static ResultDTO of(Result result, List<Feedback> filteredFeedback) {
        SubmissionDTO submissionDTO = null;
        if (Hibernate.isInitialized(result.getSubmission()) && result.getSubmission() != null) {
            submissionDTO = SubmissionDTO.of(result.getSubmission());
        }
        var feedbackDTOs = filteredFeedback.stream().map(FeedbackDTO::of).toList();
        return new ResultDTO(result.getId(), result.getCompletionDate(), result.isSuccessful(), result.getScore(), result.isRated(), submissionDTO,
                ParticipationDTO.of(result.getParticipation()), feedbackDTOs, result.getAssessmentType(), result.hasComplaint(), result.isExampleResult(),
                result.getTestCaseCount(), result.getPassedTestCaseCount(), result.getCodeIssueCount());
    }
}
