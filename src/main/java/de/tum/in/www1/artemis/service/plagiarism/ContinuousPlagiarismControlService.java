package de.tum.in.www1.artemis.service.plagiarism;

import java.time.ZonedDateTime;
import java.util.Set;
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
import de.tum.in.www1.artemis.domain.enumeration.DisplayPriority;
import de.tum.in.www1.artemis.domain.metis.Post;
import de.tum.in.www1.artemis.domain.modeling.ModelingExercise;
import de.tum.in.www1.artemis.domain.plagiarism.PlagiarismCase;
import de.tum.in.www1.artemis.domain.plagiarism.PlagiarismComparison;
import de.tum.in.www1.artemis.domain.plagiarism.PlagiarismResult;
import de.tum.in.www1.artemis.domain.plagiarism.PlagiarismStatus;
import de.tum.in.www1.artemis.domain.plagiarism.PlagiarismSubmissionElement;
import de.tum.in.www1.artemis.exception.ArtemisMailException;
import de.tum.in.www1.artemis.repository.ExerciseRepository;
import de.tum.in.www1.artemis.repository.plagiarism.PlagiarismCaseRepository;
import de.tum.in.www1.artemis.repository.plagiarism.PlagiarismComparisonRepository;
import de.tum.in.www1.artemis.repository.plagiarism.PlagiarismResultRepository;
import de.tum.in.www1.artemis.service.metis.PostService;
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

    private final PlagiarismComparisonRepository plagiarismComparisonRepository;

    private final PlagiarismCaseService plagiarismCaseService;

    private final PlagiarismCaseRepository plagiarismCaseRepository;

    private final PostService postService;

    private final PlagiarismResultRepository plagiarismResultRepository;

    public ContinuousPlagiarismControlService(ExerciseRepository exerciseRepository, PlagiarismDetectionService plagiarismDetectionService,
            PlagiarismComparisonRepository plagiarismComparisonRepository, PlagiarismCaseService plagiarismCaseService, PlagiarismCaseRepository plagiarismCaseRepository,
            PostService postService, PlagiarismResultRepository plagiarismResultRepository) {
        this.exerciseRepository = exerciseRepository;
        this.plagiarismDetectionService = plagiarismDetectionService;
        this.plagiarismComparisonRepository = plagiarismComparisonRepository;
        this.plagiarismCaseService = plagiarismCaseService;
        this.plagiarismCaseRepository = plagiarismCaseRepository;
        this.postService = postService;
        this.plagiarismResultRepository = plagiarismResultRepository;
    }

    /**
     * Daily triggers plagiarism checks as a part of continuous plagiarism control.
     */
    @Scheduled(initialDelay = 15_000, fixedDelay = 30_000)
    public void executeChecks() {
        log.info("Starting continuous plagiarism control...");

        var exercises = exerciseRepository.findAllExercisesWithDueDateOnOrAfterYesterdayAndContinuousPlagiarismControlEnabledIsTrue();
        exercises.stream().filter(isBeforeDueDateOrAfterWithPostDueDateChecksEnabled).forEach(exercise -> {
            log.info("Started continuous plagiarism control for exercise: exerciseId={}, type={}.", exercise.getId(), exercise.getExerciseType());
            final long startTime = System.nanoTime();

            PlagiarismDetectionConfigHelper.createAndSaveDefaultIfNullAndCourseExercise(exercise, exerciseRepository);

            var result = executeChecksForExerciseSilencingExceptions(exercise);
            updatePlagiarismCases(result, exercise);

            log.info("Finished continuous plagiarism control for exercise: exerciseId={}, elapsed={}.", exercise.getId(), TimeLogUtil.formatDurationFrom(startTime));
        });

        log.debug("Continuous plagiarism control done.");
    }

    private PlagiarismResult<?> executeChecksForExerciseSilencingExceptions(Exercise exercise) {
        try {
            return executeChecksForExercise(exercise);
        }
        catch (Exception e) {
            // Catch all exception to keep cpc going for other exercises
            if (e instanceof ExitException) {
                log.error("Cannot check plagiarism due to a Jplag error: exerciseId={}, type={}, error={}.", exercise.getId(), exercise.getExerciseType(), e.getMessage(), e);

            }
            else {
                log.error("Cannot check plagiarism due to an unknown error: exerciseId={}, type={}, error={}.", exercise.getId(), exercise.getExerciseType(), e.getMessage(), e);
            }

            // Clean up partial or stale plagiarism results
            plagiarismResultRepository.deletePlagiarismResultsByExerciseId(exercise.getId());

            return null;
        }
    }

    private PlagiarismResult<?> executeChecksForExercise(Exercise exercise) throws Exception {
        return switch (exercise.getExerciseType()) {
            case TEXT -> plagiarismDetectionService.checkTextExercise((TextExercise) exercise);
            case PROGRAMMING -> plagiarismDetectionService.checkProgrammingExercise((ProgrammingExercise) exercise);
            case MODELING -> plagiarismDetectionService.checkModelingExercise((ModelingExercise) exercise);
            case FILE_UPLOAD, QUIZ -> null;
        };
    }

    private void updatePlagiarismCases(PlagiarismResult<?> result, Exercise exercise) {
        if (result != null) {
            addCurrentComparisonsToPlagiarismCases(result);
        }
        removeStalePlagiarismCases(exercise.getId());
    }

    private <E extends PlagiarismSubmissionElement> void addCurrentComparisonsToPlagiarismCases(PlagiarismResult<E> result) {
        result.getComparisons().forEach(comparison -> {
            comparison.setPlagiarismResult(result);
            plagiarismComparisonRepository.updatePlagiarismComparisonStatus(comparison.getId(), PlagiarismStatus.CONFIRMED);
            createOrUpdatePlagiarismCases(comparison);
        });
    }

    private void createOrUpdatePlagiarismCases(PlagiarismComparison<?> comparison) {
        var plagiarismCases = Set.of(plagiarismCaseService.createOrAddToPlagiarismCaseForStudent(comparison, comparison.getSubmissionA(), true),
                plagiarismCaseService.createOrAddToPlagiarismCaseForStudent(comparison, comparison.getSubmissionB(), true));

        plagiarismCases.stream().filter(plagiarismCase -> plagiarismCase.getPost() == null && plagiarismCase.getStudent() != null)
                .map(ContinuousPlagiarismControlService::buildCpcPost).forEach(post -> {
                    try {
                        postService.createContinuousPlagiarismControlPlagiarismCasePost(post);
                    }
                    catch (ArtemisMailException e) {
                        // Catch mail exceptions to so that notification for the second student will be delivered
                        log.error("Cannot send a cpc email: postId={}, plagiarismCaseId={}.", post.getId(), post.getPlagiarismCase().getId());
                    }
                });
    }

    private static Post buildCpcPost(PlagiarismCase plagiarismCase) {
        var post = new Post();
        post.setVisibleForStudents(true);
        post.setDisplayPriority(DisplayPriority.NONE);
        post.setPlagiarismCase(plagiarismCase);
        post.setContent(ContinuousPlagiarismControlPostContentProvider.getPostContent(plagiarismCase));
        post.setCreationDate(ZonedDateTime.now());
        return post;
    }

    private void removeStalePlagiarismCases(long exerciseId) {
        var currentPlagiarismCases = plagiarismCaseRepository.findAllCreatedByContinuousPlagiarismControlByExerciseIdWithPlagiarismSubmissions(exerciseId);
        currentPlagiarismCases.stream().filter(plagiarismCase -> plagiarismCase.getPlagiarismSubmissions().isEmpty()).forEach(plagiarismCaseRepository::delete);
    }
}
