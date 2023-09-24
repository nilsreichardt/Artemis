package de.tum.in.www1.artemis.service.plagiarism;

import static java.lang.String.format;

import java.time.ZonedDateTime;
import java.util.function.Predicate;

import org.jvnet.hk2.annotations.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import de.jplag.exceptions.ExitException;
import de.tum.in.www1.artemis.domain.Exercise;
import de.tum.in.www1.artemis.domain.ProgrammingExercise;
import de.tum.in.www1.artemis.domain.TextExercise;
import de.tum.in.www1.artemis.domain.modeling.ModelingExercise;
import de.tum.in.www1.artemis.repository.ExerciseRepository;
import de.tum.in.www1.artemis.service.util.TimeLogUtil;

/**
 * Manages continuous plagiarism control.
 */
@Service
@Component
@Profile("scheduling")
public class ContinuousPlagiarismControlService {

    private static final Logger log = LoggerFactory.getLogger(ContinuousPlagiarismControlService.class);

    private static final Predicate<Exercise> isBeforeDueDateOrAfterWithPostDueDateChecksEnabled = exercise -> exercise.getDueDate() == null
            || exercise.getDueDate().isAfter(ZonedDateTime.now()) || exercise.getPlagiarismDetectionConfig().isContinuousPlagiarismControlPostDueDateChecksEnabled();

    private final ExerciseRepository exerciseRepository;

    private final PlagiarismDetectionService plagiarismDetectionService;

    public ContinuousPlagiarismControlService(ExerciseRepository exerciseRepository, PlagiarismDetectionService plagiarismDetectionService) {
        this.exerciseRepository = exerciseRepository;
        this.plagiarismDetectionService = plagiarismDetectionService;
    }

    /**
     * Daily triggers plagiarism checks as a part of continuous plagiarism control.
     */
    @Scheduled(cron = "${artemis.scheduling.continuous-plagiarism-control-trigger-time:0 0 4 * * *}")
    public void executeChecks() {
        log.info("Starting continuous plagiarism control...");

        var exercises = exerciseRepository.findAllExercisesWithDueDateOnOrAfterYesterdayAndContinuousPlagiarismControlEnabledIsTrue();
        exercises.stream().filter(isBeforeDueDateOrAfterWithPostDueDateChecksEnabled).forEach(exercise -> {
            log.info("Started continuous plagiarism control for exercise: exerciseId={}, type={}.", exercise.getId(), exercise.getExerciseType());
            final long startTime = System.nanoTime();

            PlagiarismDetectionConfigHelper.createAndSaveDefaultIfNull(exercise, exerciseRepository);

            try {
                executeChecksForExercise(exercise);
            }
            catch (ExitException e) {
                log.error("Cannot check plagiarism due to Jplag error: exerciseId={}, type={}, error={}.", exercise.getId(), exercise.getExerciseType(), e.getMessage(), e);
            }
            catch (Exception e) {
                // Catch all exception to keep cpc going
                log.error("Cannot check plagiarism due to unknown error: exerciseId={}, type={}, error={}.", exercise.getId(), exercise.getExerciseType(), e.getMessage(), e);
            }

            log.info("Finished continuous plagiarism control for exercise: exerciseId={}, elapsed={}.", exercise.getId(), TimeLogUtil.formatDurationFrom(startTime));
        });

        log.debug("Continuous plagiarism control done.");
    }

    private void executeChecksForExercise(Exercise exercise) throws Exception {
        switch (exercise.getExerciseType()) {
            case TEXT -> plagiarismDetectionService.checkTextExercise((TextExercise) exercise);
            case PROGRAMMING -> plagiarismDetectionService.checkProgrammingExercise((ProgrammingExercise) exercise);
            case MODELING -> plagiarismDetectionService.checkModelingExercise((ModelingExercise) exercise);
            case FILE_UPLOAD, QUIZ -> throw new IllegalStateException(
                    format("Cannot check plagiarism for exercise: type=%s, id=%s.", exercise.getExerciseType(), exercise.getId()));
        }
    }
}
