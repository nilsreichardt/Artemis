package de.tum.in.www1.artemis.service.connectors.localci;

import java.time.ZonedDateTime;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;

import javax.annotation.PostConstruct;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import com.hazelcast.collection.IQueue;
import com.hazelcast.collection.ItemEvent;
import com.hazelcast.collection.ItemListener;
import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.cp.lock.FencedLock;
import com.hazelcast.map.IMap;

import de.tum.in.www1.artemis.config.ProgrammingLanguageConfiguration;
import de.tum.in.www1.artemis.domain.BuildJob;
import de.tum.in.www1.artemis.domain.ProgrammingExercise;
import de.tum.in.www1.artemis.domain.Result;
import de.tum.in.www1.artemis.domain.enumeration.BuildJobResult;
import de.tum.in.www1.artemis.domain.enumeration.RepositoryType;
import de.tum.in.www1.artemis.domain.participation.Participation;
import de.tum.in.www1.artemis.domain.participation.ProgrammingExerciseParticipation;
import de.tum.in.www1.artemis.repository.*;
import de.tum.in.www1.artemis.security.SecurityUtils;
import de.tum.in.www1.artemis.service.connectors.localci.dto.LocalCIBuildAgentInformation;
import de.tum.in.www1.artemis.service.connectors.localci.dto.LocalCIBuildJobQueueItem;
import de.tum.in.www1.artemis.service.connectors.localci.dto.LocalCIBuildResult;
import de.tum.in.www1.artemis.service.programming.ProgrammingExerciseGradingService;
import de.tum.in.www1.artemis.service.programming.ProgrammingMessagingService;
import de.tum.in.www1.artemis.web.websocket.programmingSubmission.BuildTriggerWebsocketError;

@Service
@Profile("localci")
public class LocalCISharedBuildJobQueueService {

    private static final Logger log = LoggerFactory.getLogger(LocalCISharedBuildJobQueueService.class);

    private final HazelcastInstance hazelcastInstance;

    private final IQueue<LocalCIBuildJobQueueItem> queue;

    private final ThreadPoolExecutor localCIBuildExecutorService;

    private final LocalCIBuildJobManagementService localCIBuildJobManagementService;

    private final ProgrammingLanguageConfiguration programmingLanguageConfiguration;

    private final ParticipationRepository participationRepository;

    private final ProgrammingExerciseGradingService programmingExerciseGradingService;

    private final ProgrammingMessagingService programmingMessagingService;

    private final ProgrammingExerciseRepository programmingExerciseRepository;

    private final BuildJobRepository buildJobRepository;

    /**
     * Map of build jobs currently being processed across all nodes
     */
    private final IMap<String, LocalCIBuildJobQueueItem> processingJobs;

    private final IMap<String, LocalCIBuildAgentInformation> buildAgentInformation;

    private final AtomicInteger localProcessingJobs = new AtomicInteger(0);

    /**
     * Lock to prevent multiple nodes from processing the same build job.
     */
    private final FencedLock sharedLock;

    /**
     * Lock for operations on single instance.
     */
    private final ReentrantLock instanceLock = new ReentrantLock();

    public LocalCISharedBuildJobQueueService(HazelcastInstance hazelcastInstance, ExecutorService localCIBuildExecutorService,
            LocalCIBuildJobManagementService localCIBuildJobManagementService, ProgrammingLanguageConfiguration programmingLanguageConfiguration,
            ParticipationRepository participationRepository, ProgrammingExerciseGradingService programmingExerciseGradingService,
            ProgrammingMessagingService programmingMessagingService, ProgrammingExerciseRepository programmingExerciseRepository, BuildJobRepository buildJobRepository) {
        this.hazelcastInstance = hazelcastInstance;
        this.localCIBuildExecutorService = (ThreadPoolExecutor) localCIBuildExecutorService;
        this.localCIBuildJobManagementService = localCIBuildJobManagementService;
        this.programmingLanguageConfiguration = programmingLanguageConfiguration;
        this.participationRepository = participationRepository;
        this.programmingExerciseGradingService = programmingExerciseGradingService;
        this.programmingMessagingService = programmingMessagingService;
        this.programmingExerciseRepository = programmingExerciseRepository;
        this.buildJobRepository = buildJobRepository;
        this.buildAgentInformation = this.hazelcastInstance.getMap("buildAgentInformation");
        this.processingJobs = this.hazelcastInstance.getMap("processingJobs");
        this.sharedLock = this.hazelcastInstance.getCPSubsystem().getLock("buildJobQueueLock");
        this.queue = this.hazelcastInstance.getQueue("buildJobQueue");
    }

    /**
     * Add listener to the shared build job queue.
     */
    @PostConstruct
    public void addListener() {
        this.queue.addItemListener(new QueuedBuildJobItemListener(), true);
    }

    /**
     * Create build job item object and add it to the queue.
     *
     * @param name              name of the build job
     * @param participationId   participation id of the build job
     * @param repositoryName    name of the repository to be build
     * @param repositoryType    type of the repository to be build
     * @param commitHash        commit hash of the build job
     * @param submissionDate    submission date of the build job
     * @param priority          priority of the build job
     * @param courseId          course id of the build job
     * @param triggeredByPushTo type of the repository that was pushed to and triggered the build job
     */
    public void addBuildJob(String name, long participationId, String repositoryName, RepositoryType repositoryType, String commitHash, ZonedDateTime submissionDate, int priority,
            long courseId, RepositoryType triggeredByPushTo) {
        LocalCIBuildJobQueueItem buildJobQueueItem = new LocalCIBuildJobQueueItem((String.valueOf(participationId) + submissionDate.toInstant().toEpochMilli()), name, null,
                participationId, repositoryName, repositoryType, commitHash, submissionDate, 0, null, null, priority, courseId, triggeredByPushTo, null);
        queue.add(buildJobQueueItem);
    }

    public List<LocalCIBuildJobQueueItem> getQueuedJobs() {
        return queue.stream().toList();
    }

    public List<LocalCIBuildJobQueueItem> getProcessingJobs() {
        return processingJobs.values().stream().toList();
    }

    public List<LocalCIBuildJobQueueItem> getQueuedJobsForCourse(long courseId) {
        return queue.stream().filter(job -> job.courseId() == courseId).toList();
    }

    public List<LocalCIBuildJobQueueItem> getProcessingJobsForCourse(long courseId) {
        return processingJobs.values().stream().filter(job -> job.courseId() == courseId).toList();
    }

    public List<LocalCIBuildAgentInformation> getBuildAgentInformation() {
        // Remove build agent information of offline nodes
        removeOfflineNodes();
        return buildAgentInformation.values().stream().toList();
    }

    /**
     * Save a finished build job to the database.
     *
     * @param queueItem           the build job object from the queue
     * @param result              the result of the build job (SUCCESSFUL, FAILED, CANCELLED)
     * @param buildCompletionDate the date when the build job was completed
     * @param participation       the participation for which the build job was executed
     */
    public void saveFinishedBuildJob(LocalCIBuildJobQueueItem queueItem, BuildJobResult result, ZonedDateTime buildCompletionDate, ProgrammingExerciseParticipation participation) {
        try {
            BuildJob buildJob = new BuildJob();
            buildJob.setName(queueItem.name());
            buildJob.setExerciseId(participation.getProgrammingExercise().getId());
            buildJob.setCourseId(queueItem.courseId());
            buildJob.setParticipationId(queueItem.participationId());
            buildJob.setBuildAgentAddress(queueItem.buildAgentAddress());
            buildJob.setBuildStartDate(queueItem.buildStartDate());
            buildJob.setBuildCompletionDate(buildCompletionDate);
            buildJob.setRepositoryType(queueItem.repositoryType());
            buildJob.setRepositoryName(queueItem.repositoryName());
            buildJob.setCommitHash(queueItem.commitHash());
            buildJob.setRetryCount(queueItem.retryCount());
            buildJob.setPriority(queueItem.priority());
            buildJob.setTriggeredByPushTo(queueItem.triggeredByPushTo());
            buildJob.setBuildJobResult(result);
            buildJob.setDockerImage(queueItem.dockerImage());

            buildJobRepository.save(buildJob);
        }
        catch (Exception e) {
            log.error("Could not save build job to database", e);
        }
    }

    /**
     * Remove all queued build jobs for a participation from the shared build job queue.
     *
     * @param participationId id of the participation
     */
    public void removeQueuedJobsForParticipation(long participationId) {
        sharedLock.lock();
        try {
            List<LocalCIBuildJobQueueItem> toRemove = new ArrayList<>();
            for (LocalCIBuildJobQueueItem job : queue) {
                if (job.participationId() == participationId) {
                    toRemove.add(job);
                }
            }
            queue.removeAll(toRemove);
        }
        finally {
            sharedLock.unlock();
        }
    }

    /**
     * Wait 1 minute after startup and then every 1 minute update the build agent information of the local hazelcast member.
     * This is necessary because the build agent information is not updated automatically when a node joins the cluster.
     */
    @Scheduled(initialDelay = 60000, fixedRate = 60000) // 1 minute initial delay, 1 minute fixed rate
    public void updateBuildAgentInformation() {
        // Remove build agent information of offline nodes
        removeOfflineNodes();

        // Add build agent information of local hazelcast member to map if not already present
        if (!buildAgentInformation.containsKey(hazelcastInstance.getCluster().getLocalMember().getAddress().toString())) {
            updateLocalBuildAgentInformation();
        }
    }

    /**
     * Check every 10 seconds whether the node has at least one thread available for a new build job.
     * If so, process the next build job.
     * This is a backup mechanism in case the build queue is not empty, no new build jobs are entering the queue and the
     * node otherwise stopped checking for build jobs in the queue.
     */
    @Scheduled(fixedRate = 10000)
    public void checkForBuildJobs() {
        checkAvailabilityAndProcessNextBuild();
    }

    /**
     * Checks whether the node has at least one thread available for a new build job.
     * If so, process the next build job.
     */
    private void checkAvailabilityAndProcessNextBuild() {
        // Check conditions before acquiring the lock to avoid unnecessary locking
        if (!nodeIsAvailable()) {
            // Add build agent information of local hazelcast member to map if not already present
            if (!buildAgentInformation.containsKey(hazelcastInstance.getCluster().getLocalMember().getAddress().toString())) {
                updateLocalBuildAgentInformation();
            }

            log.debug("Node has no available threads currently");
            return;
        }

        if (queue.isEmpty()) {
            return;
        }

        instanceLock.lock();
        try {
            // Recheck conditions after acquiring the lock to ensure they are still valid
            if (!nodeIsAvailable() || queue.isEmpty()) {
                return;
            }

            LocalCIBuildJobQueueItem buildJob;

            // Lock the queue to prevent multiple nodes from processing the same build job
            sharedLock.lock();
            try {
                buildJob = addToProcessingJobs();
            }
            finally {
                sharedLock.unlock();
            }
            processBuild(buildJob);
        }
        finally {
            instanceLock.unlock();
        }
    }

    private LocalCIBuildJobQueueItem addToProcessingJobs() {
        LocalCIBuildJobQueueItem buildJob = queue.poll();
        if (buildJob != null) {
            String hazelcastMemberAddress = hazelcastInstance.getCluster().getLocalMember().getAddress().toString();
            LocalCIBuildJobQueueItem processingJob = new LocalCIBuildJobQueueItem(buildJob.id(), buildJob.name(), hazelcastMemberAddress, buildJob.participationId(),
                    buildJob.repositoryName(), buildJob.repositoryType(), buildJob.commitHash(), buildJob.submissionDate(), buildJob.retryCount(), ZonedDateTime.now(), null,
                    buildJob.priority(), buildJob.courseId(), buildJob.triggeredByPushTo(), null);
            processingJobs.put(processingJob.id(), processingJob);
            localProcessingJobs.incrementAndGet();

            updateLocalBuildAgentInformation();
            return processingJob;
        }
        return null;
    }

    private void updateLocalBuildAgentInformation() {
        // Add/update
        String memberAddress = hazelcastInstance.getCluster().getLocalMember().getAddress().toString();
        List<LocalCIBuildJobQueueItem> processingJobsOfMember = getProcessingJobsOfNode(memberAddress);
        int numberOfCurrentBuildJobs = processingJobsOfMember.size();
        int maxNumberOfConcurrentBuilds = localCIBuildExecutorService.getMaximumPoolSize();
        LocalCIBuildAgentInformation info = new LocalCIBuildAgentInformation(memberAddress, maxNumberOfConcurrentBuilds, numberOfCurrentBuildJobs, processingJobsOfMember);
        buildAgentInformation.put(memberAddress, info);
    }

    private List<LocalCIBuildJobQueueItem> getProcessingJobsOfNode(String memberAddress) {
        return processingJobs.values().stream().filter(job -> Objects.equals(job.buildAgentAddress(), memberAddress)).toList();
    }

    private void removeOfflineNodes() {
        List<String> memberAddresses = hazelcastInstance.getCluster().getMembers().stream().map(member -> member.getAddress().toString()).toList();
        for (String key : buildAgentInformation.keySet()) {
            if (!memberAddresses.contains(key)) {
                buildAgentInformation.remove(key);
            }
        }
    }

    /**
     * Process a build job by submitting it to the local CI executor service.
     * On completion, check for next job.
     */
    private void processBuild(LocalCIBuildJobQueueItem buildJob) {
        // The 'user' is not properly logged into Artemis, this leads to an issue when accessing custom repository methods.
        // Therefore, a mock auth object has to be created.
        SecurityUtils.setAuthorizationObject();

        if (buildJob == null) {
            return;
        }

        log.info("Processing build job: {}", buildJob);
        String commitHash = buildJob.commitHash();
        boolean isRetry = buildJob.retryCount() >= 1;

        ProgrammingExerciseParticipation participation;

        // Participation might not be persisted in the database yet or it has been deleted in the meantime
        try {
            participation = retrieveParticipationWithRetry(buildJob.participationId());
        }
        catch (IllegalStateException e) {
            log.error("Cannot process build job for participation with id {} because it could not be retrieved from the database.", buildJob.participationId());
            processingJobs.remove(buildJob.id());
            localProcessingJobs.decrementAndGet();
            updateLocalBuildAgentInformation();
            checkAvailabilityAndProcessNextBuild();
            return;
        }
        catch (Exception e) {
            log.error("Cannot process build job for participation with id {} because of an unexpected error.", buildJob.participationId(), e);
            processingJobs.remove(buildJob.id());
            localProcessingJobs.decrementAndGet();
            updateLocalBuildAgentInformation();
            checkAvailabilityAndProcessNextBuild();
            return;
        }

        // For some reason, it is possible that the participation object does not have the programming exercise
        if (participation.getProgrammingExercise() == null) {
            SecurityUtils.setAuthorizationObject();
            participation.setProgrammingExercise(programmingExerciseRepository.findByParticipationIdOrElseThrow(participation.getId()));
        }

        ProgrammingExercise programmingExercise = participation.getProgrammingExercise();
        String dockerImage;
        try {
            dockerImage = programmingExercise.getWindfile().getMetadata().getDocker().getImage();
        }
        catch (NullPointerException e) {
            log.warn("Could not retrieve Docker image from windfile metadata for programming exercise {}. Using default Docker image instead.", programmingExercise.getId());
            dockerImage = programmingLanguageConfiguration.getImage(programmingExercise.getProgrammingLanguage(), Optional.ofNullable(programmingExercise.getProjectType()));
        }
        LocalCIBuildJobQueueItem updatedJob = new LocalCIBuildJobQueueItem(buildJob.id(), buildJob.name(), buildJob.buildAgentAddress(), buildJob.participationId(),
                buildJob.repositoryName(), buildJob.repositoryType(), buildJob.commitHash(), buildJob.submissionDate(), buildJob.retryCount(), buildJob.buildStartDate(), null,
                buildJob.priority(), buildJob.courseId(), buildJob.triggeredByPushTo(), dockerImage);

        processingJobs.put(buildJob.id(), updatedJob);

        boolean isPushToTestOrAuxRepository = buildJob.triggeredByPushTo() == RepositoryType.TESTS || buildJob.triggeredByPushTo() == RepositoryType.AUXILIARY;

        CompletableFuture<LocalCIBuildResult> futureResult = localCIBuildJobManagementService.executeBuildJob(participation, commitHash, isRetry, isPushToTestOrAuxRepository,
                updatedJob.id(), dockerImage);
        futureResult.thenAccept(buildResult -> {

            ZonedDateTime buildCompletionDate = ZonedDateTime.now();

            // Do not process the result if the participation has been deleted in the meantime
            Optional<Participation> participationOptional = participationRepository.findById(participation.getId());
            if (participationOptional.isPresent()) {
                SecurityUtils.setAuthorizationObject();
                Result result = programmingExerciseGradingService.processNewProgrammingExerciseResult(participation, buildResult);
                if (result != null) {
                    programmingMessagingService.notifyUserAboutNewResult(result, participation);
                }
                else {
                    programmingMessagingService.notifyUserAboutSubmissionError((Participation) participation,
                            new BuildTriggerWebsocketError("Result could not be processed", participation.getId()));
                }
            }
            else {
                log.warn("Participation with id {} has been deleted. Cancelling the processing of the build result.", participation.getId());
            }

            // save build job to database
            saveFinishedBuildJob(updatedJob, BuildJobResult.SUCCESSFUL, buildCompletionDate, participation);

            // after processing a build job, remove it from the processing jobs
            processingJobs.remove(updatedJob.id());
            localProcessingJobs.decrementAndGet();
            updateLocalBuildAgentInformation();

            // process next build job if node is available
            checkAvailabilityAndProcessNextBuild();

        }).exceptionally(ex -> {
            ZonedDateTime buildCompletionDate = ZonedDateTime.now();
            if (ex.getCause() instanceof CancellationException && ex.getMessage().equals("Build job with id " + buildJob.id() + " was cancelled.")) {
                localProcessingJobs.decrementAndGet();
                updateLocalBuildAgentInformation();
                saveFinishedBuildJob(updatedJob, BuildJobResult.CANCELLED, buildCompletionDate, participation);
            }
            else {
                log.error("Error while processing build job: {}", updatedJob, ex);

                processingJobs.remove(updatedJob.id());
                localProcessingJobs.decrementAndGet();
                updateLocalBuildAgentInformation();

                if (isRetry) {
                    log.error("Build job failed for the second time: {}", updatedJob);
                    saveFinishedBuildJob(updatedJob, BuildJobResult.FAILED, buildCompletionDate, participation);
                    return null;
                }

                // Do not requeue the build job if the participation has been deleted in the meantime
                SecurityUtils.setAuthorizationObject();
                Optional<Participation> participationOptional = participationRepository.findById(participation.getId());
                if (participationOptional.isPresent()) {
                    log.warn("Requeueing failed build job: {}", updatedJob);
                    LocalCIBuildJobQueueItem requeuedBuildJob = new LocalCIBuildJobQueueItem(updatedJob.id(), updatedJob.name(), null, updatedJob.participationId(),
                            updatedJob.repositoryName(), updatedJob.repositoryType(), updatedJob.commitHash(), updatedJob.submissionDate(), updatedJob.retryCount() + 1, null, null,
                            updatedJob.priority(), updatedJob.courseId(), updatedJob.triggeredByPushTo(), null);
                    queue.add(requeuedBuildJob);
                }
                else {
                    log.warn("Participation with id {} has been deleted. Cancelling the requeueing of the build job.", participation.getId());
                }
                saveFinishedBuildJob(updatedJob, BuildJobResult.FAILED, buildCompletionDate, participation);
            }
            checkAvailabilityAndProcessNextBuild();
            return null;
        });
    }

    /**
     * Checks whether the node has at least one thread available for a new build job.
     */
    private boolean nodeIsAvailable() {
        log.debug("Currently processing jobs on this node: {}, maximum pool size of thread executor : {}", localProcessingJobs.get(),
                localCIBuildExecutorService.getMaximumPoolSize());
        return localProcessingJobs.get() < localCIBuildExecutorService.getMaximumPoolSize();
    }

    /**
     * Retrieve participation from database with retries.
     * This is necessary because the participation might not be persisted in the database yet.
     *
     * @param participationId id of the participation
     */
    private ProgrammingExerciseParticipation retrieveParticipationWithRetry(Long participationId) {
        int maxRetries = 5;
        int retries = 0;
        ProgrammingExerciseParticipation participation;
        Optional<Participation> tempParticipation;
        while (retries < maxRetries) {
            SecurityUtils.setAuthorizationObject();
            tempParticipation = participationRepository.findById(participationId);
            if (tempParticipation.isPresent()) {
                participation = (ProgrammingExerciseParticipation) tempParticipation.get();
                return participation;
            }
            else {
                log.debug("Could not retrieve participation with id {} from database", participationId);
                log.info("Retrying to retrieve participation with id {} from database", participationId);
                retries++;
                try {
                    Thread.sleep(1000);
                }
                catch (InterruptedException e1) {
                    log.error("Error while waiting for participation with id {} to be persisted in database", participationId, e1);
                }
            }
        }
        throw new IllegalStateException("Could not retrieve participation with id " + participationId + " from database after " + maxRetries + " retries.");
    }

    /**
     * Cancel a build job by removing it from the queue or stopping the build process.
     *
     * @param buildJobId id of the build job to cancel
     */
    public void cancelBuildJob(String buildJobId) {
        sharedLock.lock();
        try {
            // Remove build job if it is queued
            if (queue.stream().anyMatch(job -> Objects.equals(job.id(), buildJobId))) {
                List<LocalCIBuildJobQueueItem> toRemove = new ArrayList<>();
                for (LocalCIBuildJobQueueItem job : queue) {
                    if (Objects.equals(job.id(), buildJobId)) {
                        toRemove.add(job);
                    }
                }
                queue.removeAll(toRemove);
            }
            else {
                // Cancel build job if it is currently being processed
                LocalCIBuildJobQueueItem buildJob = processingJobs.remove(buildJobId);
                if (buildJob != null) {
                    localCIBuildJobManagementService.triggerBuildJobCancellation(buildJobId);
                }
            }
        }
        finally {
            sharedLock.unlock();
        }
    }

    /**
     * Cancel all queued build jobs.
     */
    public void cancelAllQueuedBuildJobs() {
        sharedLock.lock();
        try {
            log.debug("Cancelling all queued build jobs");
            queue.clear();
        }
        finally {
            sharedLock.unlock();
        }
    }

    /**
     * Cancel all running build jobs.
     */
    public void cancelAllRunningBuildJobs() {
        sharedLock.lock();
        try {
            for (LocalCIBuildJobQueueItem buildJob : processingJobs.values()) {
                cancelBuildJob(buildJob.id());
            }
        }
        finally {
            sharedLock.unlock();
        }
    }

    /**
     * Cancel all queued build jobs for a course.
     *
     * @param courseId id of the course
     */
    public void cancelAllQueuedBuildJobsForCourse(long courseId) {
        sharedLock.lock();
        try {
            List<LocalCIBuildJobQueueItem> toRemove = new ArrayList<>();
            for (LocalCIBuildJobQueueItem job : queue) {
                if (job.courseId() == courseId) {
                    toRemove.add(job);
                }
            }
            queue.removeAll(toRemove);
        }
        finally {
            sharedLock.unlock();
        }
    }

    /**
     * Cancel all running build jobs for a course.
     *
     * @param courseId id of the course
     */
    public void cancelAllRunningBuildJobsForCourse(long courseId) {
        for (LocalCIBuildJobQueueItem buildJob : processingJobs.values()) {
            if (buildJob.courseId() == courseId) {
                cancelBuildJob(buildJob.id());
            }
        }
    }

    private class QueuedBuildJobItemListener implements ItemListener<LocalCIBuildJobQueueItem> {

        @Override
        public void itemAdded(ItemEvent<LocalCIBuildJobQueueItem> event) {
            log.debug("CIBuildJobQueueItem added to queue: {}", event.getItem());
            checkAvailabilityAndProcessNextBuild();
        }

        @Override
        public void itemRemoved(ItemEvent<LocalCIBuildJobQueueItem> event) {
            log.debug("CIBuildJobQueueItem removed from queue: {}", event.getItem());
        }
    }
}
