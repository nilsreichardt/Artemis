package de.tum.in.www1.artemis.service.connectors.athena;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.jsonPath;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import de.tum.in.www1.artemis.AbstractAthenaTest;
import de.tum.in.www1.artemis.domain.*;
import de.tum.in.www1.artemis.exception.NetworkingException;
import de.tum.in.www1.artemis.exercise.programmingexercise.ProgrammingExerciseUtilService;
import de.tum.in.www1.artemis.exercise.textexercise.TextExerciseUtilService;
import de.tum.in.www1.artemis.service.dto.athena.ProgrammingFeedbackDTO;
import de.tum.in.www1.artemis.service.dto.athena.TextFeedbackDTO;

class AthenaFeedbackSuggestionsServiceTest extends AbstractAthenaTest {

    @Autowired
    private AthenaFeedbackSuggestionsService athenaFeedbackSuggestionsService;

    @Autowired
    private TextExerciseUtilService textExerciseUtilService;

    @Autowired
    private ProgrammingExerciseUtilService programmingExerciseUtilService;

    private TextExercise textExercise;

    private TextSubmission textSubmission;

    private ProgrammingExercise programmingExercise;

    private ProgrammingSubmission programmingSubmission;

    @BeforeEach
    void setUp() {
        athenaRequestMockProvider.enableMockingOfRequests();

        textExercise = textExerciseUtilService.createSampleTextExercise(null);
        textSubmission = new TextSubmission(2L).text("This is a text submission");

        programmingExercise = programmingExerciseUtilService.createSampleProgrammingExercise();
        programmingSubmission = new ProgrammingSubmission();
        programmingSubmission.setId(3L);
    }

    @Test
    void testFeedbackSuggestionsText() throws NetworkingException {
        athenaRequestMockProvider.mockGetFeedbackSuggestionsAndExpect("text", jsonPath("$.exercise.id").value(textExercise.getId()),
                jsonPath("$.exercise.title").value(textExercise.getTitle()), jsonPath("$.submission.id").value(textSubmission.getId()),
                jsonPath("$.submission.text").value(textSubmission.getText()));
        List<TextFeedbackDTO> suggestions = athenaFeedbackSuggestionsService.getTextFeedbackSuggestions(textExercise, textSubmission);
        assertThat(suggestions.get(0).title()).isEqualTo("Not so good");
        assertThat(suggestions.get(0).indexStart()).isEqualTo(3);
    }

    @Test
    void testFeedbackSuggestionsProgramming() throws NetworkingException {
        athenaRequestMockProvider.mockGetFeedbackSuggestionsAndExpect("programming", jsonPath("$.exercise.id").value(programmingExercise.getId()),
                jsonPath("$.exercise.title").value(programmingExercise.getTitle()), jsonPath("$.submission.id").value(programmingSubmission.getId()),
                jsonPath("$.submission.repositoryUrl").value("https://artemislocal.ase.in.tum.de/api/public/athena/programming-exercises/2/submissions/3/repository"));
        List<ProgrammingFeedbackDTO> suggestions = athenaFeedbackSuggestionsService.getProgrammingFeedbackSuggestions(programmingExercise, programmingSubmission);
        assertThat(suggestions.get(0).title()).isEqualTo("Not so good");
        assertThat(suggestions.get(0).lineStart()).isEqualTo(3);
    }
}
