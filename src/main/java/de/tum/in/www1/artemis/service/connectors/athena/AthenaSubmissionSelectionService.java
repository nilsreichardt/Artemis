package de.tum.in.www1.artemis.service.connectors.athena;

import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.annotation.JsonProperty;

import de.tum.in.www1.artemis.domain.Exercise;
import de.tum.in.www1.artemis.exception.NetworkingException;
import de.tum.in.www1.artemis.service.dto.athena.ExerciseDTO;

/**
 * Service for selecting the "best" submission to assess right now using Athena, e.g. by the highest information gain.
 * Assumes that submissions have already been sent to Athena (it only sends submission IDs to choose from).
 * The default choice if Athena does not respond is to choose a random submission.
 */
@Service
@Profile("athena")
public class AthenaSubmissionSelectionService {

    private static final Logger log = LoggerFactory.getLogger(AthenaSubmissionSelectionService.class);

    private final AthenaConnector<RequestDTO, ResponseDTO> connector;

    private final AthenaModuleUrlHelper athenaModuleUrlHelper;

    private final AthenaDTOConverter athenaDTOConverter;

    private record RequestDTO(ExerciseDTO exercise, List<Long> submissionIds// Athena just needs submission IDs => quicker request, because less data is sent
    ) {
    }

    private record ResponseDTO(@JsonProperty("data") long submissionId // submission ID to choose, or -1 if no submission was explicitly chosen
    ) {
    }

    /**
     * Create a new AthenaSubmissionSelectionService
     * Responses should be fast, and it's not too bad if it fails. Therefore, we use a very short timeout for requests.
     */
    public AthenaSubmissionSelectionService(@Qualifier("veryShortTimeoutAthenaRestTemplate") RestTemplate veryShortTimeoutAthenaRestTemplate,
            AthenaModuleUrlHelper athenaModuleUrlHelper, AthenaDTOConverter athenaDTOConverter) {
        connector = new AthenaConnector<>(veryShortTimeoutAthenaRestTemplate, ResponseDTO.class);
        this.athenaModuleUrlHelper = athenaModuleUrlHelper;
        this.athenaDTOConverter = athenaDTOConverter;
    }

    /**
     * Fetches the proposed submission for a given exercise from Athena.
     * It is not guaranteed that you get a valid submission ID, so you need to check for existence yourself.
     *
     * @param exercise      the exercise to get the proposed Submission for
     * @param submissionIds IDs of assessable submissions of the exercise
     * @return a submission ID suggested by the Athena submission selector (e.g. chosen by the highest information gain)
     * @throws IllegalArgumentException if exercise isn't automatically assessable
     */
    public Optional<Long> getProposedSubmissionId(Exercise exercise, List<Long> submissionIds) {
        if (!exercise.getFeedbackSuggestionsEnabled()) {
            throw new IllegalArgumentException("The Exercise does not have feedback suggestions enabled.");
        }
        if (submissionIds.isEmpty()) {
            return Optional.empty();
        }

        log.debug("Start Athena Submission Selection Service for Exercise '{}' (#{}).", exercise.getTitle(), exercise.getId());

        log.info("Calling Athena to calculate next proposed submissions for {} submissions.", submissionIds.size());

        try {
            final RequestDTO request = new RequestDTO(athenaDTOConverter.ofExercise(exercise), submissionIds);
            // allow no retries because this should be fast and it's not too bad if it fails
            ResponseDTO response = connector.invokeWithRetry(athenaModuleUrlHelper.getAthenaModuleUrl(exercise.getExerciseType()) + "/select_submission", request, 0);
            log.info("Athena to calculate next proposes submissions responded: {}", response.submissionId);
            if (response.submissionId == -1) {
                return Optional.empty();
            }
            return Optional.of(response.submissionId);
        }
        catch (NetworkingException | HttpClientErrorException | HttpServerErrorException exception) {
            // We don't want to crash because of this because it would break the assessment process
            log.error("Exception occurred while calling Athena: {}", exception.getMessage());
        }

        return Optional.empty();
    }
}
