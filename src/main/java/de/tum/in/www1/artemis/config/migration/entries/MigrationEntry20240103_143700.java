package de.tum.in.www1.artemis.config.migration.entries;

import java.net.MalformedURLException;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.*;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Component;

import com.google.common.collect.Lists;

import de.tum.in.www1.artemis.config.migration.MigrationEntry;
import de.tum.in.www1.artemis.domain.participation.*;
import de.tum.in.www1.artemis.repository.ProgrammingExerciseRepository;
import de.tum.in.www1.artemis.repository.SolutionProgrammingExerciseParticipationRepository;
import de.tum.in.www1.artemis.service.connectors.aeolus.AeolusBuildScriptGenerationService;
import de.tum.in.www1.artemis.service.connectors.localvc.LocalVCService;

@Component
public class MigrationEntry20240103_143700 extends MigrationEntry {

    private static final int BATCH_SIZE = 100;

    private static final int MAX_THREAD_COUNT = 1;

    private static final String ERROR_MESSAGE = "Failed to migrate programming exercises within nine hours. Aborting migration.";

    private static final int TIMEOUT_IN_HOURS = 9;

    private static final List<String> MIGRATABLE_PROFILES = List.of("bitbucket", "localvc");

    private final Logger log = LoggerFactory.getLogger(MigrationEntry20240103_143700.class);

    private final ProgrammingExerciseRepository programmingExerciseRepository;

    private final SolutionProgrammingExerciseParticipationRepository solutionProgrammingExerciseParticipationRepository;

    private final Optional<LocalVCService> localVCService;

    private final Environment environment;

    private final CopyOnWriteArrayList<ProgrammingExerciseParticipation> errorList = new CopyOnWriteArrayList<>();

    private final Optional<AeolusBuildScriptGenerationService> aeolusBuildScriptGenerationService;

    // @Value("${artemis.version-control.default-branch}") somehow this is not working -> main it is
    protected String defaultBranch = "main";

    public MigrationEntry20240103_143700(ProgrammingExerciseRepository programmingExerciseRepository, Environment environment,
            SolutionProgrammingExerciseParticipationRepository solutionProgrammingExerciseParticipationRepository, Optional<LocalVCService> localVCService,
            Optional<AeolusBuildScriptGenerationService> aeolusBuildScriptGenerationService) throws MalformedURLException {
        this.programmingExerciseRepository = programmingExerciseRepository;
        this.environment = environment;
        this.solutionProgrammingExerciseParticipationRepository = solutionProgrammingExerciseParticipationRepository;
        this.localVCService = localVCService;
        this.aeolusBuildScriptGenerationService = aeolusBuildScriptGenerationService;
    }

    @Override
    public void execute() {
        List<String> activeProfiles = List.of(environment.getActiveProfiles());
        if (!new HashSet<>(activeProfiles).containsAll(MIGRATABLE_PROFILES)) {
            log.info("Migration will be skipped and marked run because the system does not support a tech-stack that requires this migration: {}",
                    List.of(environment.getActiveProfiles()));
            return;
        }

        var programmingExerciseCount = programmingExerciseRepository.count();

        if (programmingExerciseCount == 0) {
            // no exercises to change, migration complete
            return;
        }

        log.info("Will migrate {} programming exercises. This might take a while", programmingExerciseCount);
        // Number of full batches. The last batch might be smaller
        long totalFullBatchCount = programmingExerciseCount / BATCH_SIZE;
        int threadCount = (int) Math.max(1, Math.min(totalFullBatchCount, MAX_THREAD_COUNT));

        // Use fixed thread pool to prevent loading too many exercises into memory at once
        ExecutorService executorService = Executors.newFixedThreadPool(threadCount);

        /*
         * migrate the solution participations, we ignore the others
         */
        var solutionCount = solutionProgrammingExerciseParticipationRepository.count();
        log.info("Found {} solution participations to migrate.", solutionCount);
        for (int currentPageStart = 0; currentPageStart < solutionCount; currentPageStart += BATCH_SIZE) {
            Pageable pageable = PageRequest.of(currentPageStart / BATCH_SIZE, BATCH_SIZE);
            var solutionParticipationPage = solutionProgrammingExerciseParticipationRepository.findAll(pageable);
            log.info("Will migrate {} solution participations in batch.", solutionParticipationPage.getNumberOfElements());
            var solutionParticipationsPartitions = Lists.partition(solutionParticipationPage.toList(), threadCount);
            for (var solutionParticipations : solutionParticipationsPartitions) {
                executorService.submit(() -> migrateSolutions(solutionParticipations));
            }
        }

        log.info("Submitted all solution participations to thread pool for migration.");

        // Wait for all threads to finish
        executorService.shutdown();

        try {
            boolean finished = executorService.awaitTermination(TIMEOUT_IN_HOURS, TimeUnit.HOURS);
            if (!finished) {
                log.error(ERROR_MESSAGE);
                if (executorService.awaitTermination(1, TimeUnit.MINUTES)) {
                    log.error("Failed to cancel all migration threads. Some threads are still running.");
                }
                throw new RuntimeException(ERROR_MESSAGE);
            }
        }
        catch (InterruptedException e) {
            log.error(ERROR_MESSAGE);
            executorService.shutdownNow();
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        }

        log.info("Finished migrating programming exercises and student participations");
        evaluateErrorList();
    }

    private void migrateSolutions(List<SolutionProgrammingExerciseParticipation> solutionParticipations) {
        for (var solutionParticipation : solutionParticipations) {
            try {
                var programmingExercise = solutionParticipation.getProgrammingExercise();
            }
            catch (Exception e) {
                log.error("Failed to migrate solution participation with id {}", solutionParticipation.getId(), e);
                errorList.add(solutionParticipation);
            }
        }
    }

    /**
     * Evaluates the error map and prints the errors to the log.
     */
    private void evaluateErrorList() {
        if (errorList.isEmpty()) {
            log.info("Successfully migrated all programming exercises");
            return;
        }

        List<Long> failedTemplateExercises = errorList.stream().filter(participation -> participation instanceof TemplateProgrammingExerciseParticipation)
                .map(participation -> participation.getProgrammingExercise().getId()).toList();
        List<Long> failedSolutionExercises = errorList.stream().filter(participation -> participation instanceof SolutionProgrammingExerciseParticipation)
                .map(participation -> participation.getProgrammingExercise().getId()).toList();
        List<Long> failedStudentParticipations = errorList.stream().filter(participation -> participation instanceof ProgrammingExerciseStudentParticipation)
                .map(ParticipationInterface::getId).toList();

        log.error("{} failures during migration", errorList.size());
        // print each participation in a single line in the long to simplify reviewing the issues
        log.error("Errors occurred for the following participations: \n{}", errorList.stream().map(Object::toString).collect(Collectors.joining("\n")));
        log.error("Failed to migrate template build plan for exercises: {}", failedTemplateExercises);
        log.error("Failed to migrate solution build plan for exercises: {}", failedSolutionExercises);
        log.error("Failed to migrate students participations: {}", failedStudentParticipations);
        log.warn("Please check the logs for more information. If the issues are related to the external VCS/CI system, fix the issues and rerun the migration. or "
                + "fix the build plans yourself and mark the migration as run. The migration can be rerun by deleting the migration entry in the database table containing "
                + "the migration with author: {} and date_string: {} and then restarting Artemis.", author(), date());
    }

    @Override
    public String author() {
        return "reschandreas";
    }

    @Override
    public String date() {
        return "20240103_143700";
    }
}
