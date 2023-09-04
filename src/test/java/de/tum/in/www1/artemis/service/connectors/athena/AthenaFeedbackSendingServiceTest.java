package de.tum.in.www1.artemis.service.connectors.athena;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.jsonPath;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;

import de.tum.in.www1.artemis.AbstractAthenaTest;
import de.tum.in.www1.artemis.domain.*;
import de.tum.in.www1.artemis.domain.enumeration.FeedbackType;
import de.tum.in.www1.artemis.domain.participation.StudentParticipation;
import de.tum.in.www1.artemis.exercise.programmingexercise.ProgrammingExerciseUtilService;
import de.tum.in.www1.artemis.exercise.textexercise.TextExerciseUtilService;
import de.tum.in.www1.artemis.repository.TextBlockRepository;

class AthenaFeedbackSendingServiceTest extends AbstractAthenaTest {

    @Autowired
    private AthenaModuleUrlHelper athenaModuleUrlHelper;

    @Mock
    private TextBlockRepository textBlockRepository;

    @Autowired
    private TextExerciseUtilService textExerciseUtilService;

    @Autowired
    private ProgrammingExerciseUtilService programmingExerciseUtilService;

    private AthenaFeedbackSendingService athenaFeedbackSendingService;

    private TextExercise textExercise;

    private TextSubmission textSubmission;

    private Feedback textFeedback;

    private TextBlock textBlock;

    private ProgrammingExercise programmingExercise;

    private ProgrammingSubmission programmingSubmission;

    private Feedback programmingFeedback;

    @BeforeEach
    void setUp() {
        athenaFeedbackSendingService = new AthenaFeedbackSendingService(athenaRequestMockProvider.getRestTemplate(), athenaModuleUrlHelper,
                new AthenaDTOConverter(textBlockRepository));

        athenaRequestMockProvider.enableMockingOfRequests();

        textExercise = textExerciseUtilService.createSampleTextExercise(null);
        textExercise.setFeedbackSuggestionsEnabled(true);

        textSubmission = new TextSubmission(2L).text("Test - This is what the feedback references - Submission");

        textBlock = new TextBlock().startIndex(7).endIndex(46).text("This is what the feedback references").submission(textSubmission);
        textBlock.computeId();
        when(textBlockRepository.findById(textBlock.getId())).thenReturn(Optional.of(textBlock));

        textFeedback = new Feedback().type(FeedbackType.MANUAL).credits(5.0).reference(textBlock.getId());
        textFeedback.setId(3L);
        var result = new Result();
        textFeedback.setResult(result);
        var participation = new StudentParticipation();
        participation.setExercise(textExercise);
        result.setParticipation(participation);

        programmingExercise = programmingExerciseUtilService.createSampleProgrammingExercise();
        programmingExercise.setFeedbackSuggestionsEnabled(true);

        programmingSubmission = new ProgrammingSubmission();
        programmingSubmission.setParticipation(new StudentParticipation());
        programmingSubmission.getParticipation().setExercise(programmingExercise);
        programmingSubmission.setId(2L);

        programmingFeedback = new Feedback().type(FeedbackType.MANUAL).credits(5.0).reference("test");
        programmingFeedback.setId(3L);
        programmingFeedback.setReference("file:src/Test.java_line:12");
        var programmingResult = new Result();
        programmingFeedback.setResult(programmingResult);
        programmingResult.setParticipation(programmingSubmission.getParticipation());
    }

    @Test
    void testFeedbackSendingText() {
        athenaRequestMockProvider.mockSendFeedbackAndExpect("text", jsonPath("$.exercise.id").value(textExercise.getId()),
                jsonPath("$.submission.id").value(textSubmission.getId()), jsonPath("$.submission.exerciseId").value(textExercise.getId()),
                jsonPath("$.feedbacks[0].id").value(textFeedback.getId()), jsonPath("$.feedbacks[0].exerciseId").value(textExercise.getId()),
                jsonPath("$.feedbacks[0].title").value(textFeedback.getText()), jsonPath("$.feedbacks[0].description").value(textFeedback.getDetailText()),
                jsonPath("$.feedbacks[0].credits").value(textFeedback.getCredits()), jsonPath("$.feedbacks[0].credits").value(textFeedback.getCredits()),
                jsonPath("$.feedbacks[0].indexStart").value(textBlock.getStartIndex()), jsonPath("$.feedbacks[0].indexEnd").value(textBlock.getEndIndex()));

        athenaFeedbackSendingService.sendFeedback(textExercise, textSubmission, List.of(textFeedback));
    }

    @Test
    void testFeedbackSendingProgramming() {
        athenaRequestMockProvider.mockSendFeedbackAndExpect("programming", jsonPath("$.exercise.id").value(programmingExercise.getId()),
                jsonPath("$.submission.id").value(programmingSubmission.getId()), jsonPath("$.submission.exerciseId").value(programmingExercise.getId()),
                jsonPath("$.feedbacks[0].id").value(programmingFeedback.getId()), jsonPath("$.feedbacks[0].exerciseId").value(programmingExercise.getId()),
                jsonPath("$.feedbacks[0].title").value(programmingFeedback.getText()), jsonPath("$.feedbacks[0].description").value(programmingFeedback.getDetailText()),
                jsonPath("$.feedbacks[0].credits").value(programmingFeedback.getCredits()), jsonPath("$.feedbacks[0].credits").value(programmingFeedback.getCredits()),
                jsonPath("$.feedbacks[0].lineStart").value(12), jsonPath("$.feedbacks[0].lineEnd").value(12));

        athenaFeedbackSendingService.sendFeedback(programmingExercise, programmingSubmission, List.of(programmingFeedback));
    }

    @Test
    void testEmptyFeedbackNotSending() {
        athenaRequestMockProvider.ensureNoRequest();
        athenaFeedbackSendingService.sendFeedback(textExercise, textSubmission, List.of());
        athenaFeedbackSendingService.sendFeedback(programmingExercise, programmingSubmission, List.of());
    }

    @Test
    void testSendFeedbackWithFeedbackSuggestionsDisabled() {
        textExercise.setFeedbackSuggestionsEnabled(false);
        assertThatThrownBy(() -> athenaFeedbackSendingService.sendFeedback(textExercise, textSubmission, List.of(textFeedback))).isInstanceOf(IllegalArgumentException.class);
        programmingExercise.setFeedbackSuggestionsEnabled(false);
        assertThatThrownBy(() -> athenaFeedbackSendingService.sendFeedback(programmingExercise, programmingSubmission, List.of(programmingFeedback)))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
