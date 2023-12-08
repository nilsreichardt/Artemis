package de.tum.in.www1.artemis.service.connectors.localvc;

import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

import javax.servlet.http.HttpServletRequest;

import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.eclipse.jgit.errors.RepositoryNotFoundException;
import org.eclipse.jgit.lib.ObjectId;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.revwalk.RevCommit;
import org.eclipse.jgit.storage.file.FileRepositoryBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;

import de.tum.in.www1.artemis.domain.*;
import de.tum.in.www1.artemis.domain.enumeration.*;
import de.tum.in.www1.artemis.domain.participation.ProgrammingExerciseParticipation;
import de.tum.in.www1.artemis.domain.participation.SolutionProgrammingExerciseParticipation;
import de.tum.in.www1.artemis.exception.LocalCIException;
import de.tum.in.www1.artemis.exception.VersionControlException;
import de.tum.in.www1.artemis.exception.localvc.LocalVCAuthException;
import de.tum.in.www1.artemis.exception.localvc.LocalVCForbiddenException;
import de.tum.in.www1.artemis.exception.localvc.LocalVCInternalException;
import de.tum.in.www1.artemis.repository.ProgrammingExerciseRepository;
import de.tum.in.www1.artemis.repository.UserRepository;
import de.tum.in.www1.artemis.security.SecurityUtils;
import de.tum.in.www1.artemis.service.AuthorizationCheckService;
import de.tum.in.www1.artemis.service.RepositoryAccessService;
import de.tum.in.www1.artemis.service.connectors.localci.LocalCIProgrammingLanguageFeatureService;
import de.tum.in.www1.artemis.service.connectors.localci.LocalCITriggerService;
import de.tum.in.www1.artemis.service.programming.*;
import de.tum.in.www1.artemis.service.util.TimeLogUtil;
import de.tum.in.www1.artemis.web.rest.errors.AccessForbiddenException;
import de.tum.in.www1.artemis.web.rest.errors.AccessUnauthorizedException;
import de.tum.in.www1.artemis.web.rest.errors.EntityNotFoundException;
import de.tum.in.www1.artemis.web.rest.repository.RepositoryActionType;

/**
 * This service is responsible for authenticating and authorizing git requests as well as for retrieving the requested Git repositories from disk.
 * It is used by the ArtemisGitServlet, the LocalVCFetchFilter, and the LocalVCPushFilter.
 */
@Service
@Profile("localvc")
public class LocalVCServletService {

    private final Logger log = LoggerFactory.getLogger(LocalVCServletService.class);

    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    private final UserRepository userRepository;

    private final ProgrammingExerciseRepository programmingExerciseRepository;

    private final RepositoryAccessService repositoryAccessService;

    private final AuthorizationCheckService authorizationCheckService;

    private final ProgrammingExerciseParticipationService programmingExerciseParticipationService;

    private final AuxiliaryRepositoryService auxiliaryRepositoryService;

    private final LocalCITriggerService localCITriggerService;

    private final ProgrammingSubmissionService programmingSubmissionService;

    private final ProgrammingMessagingService programmingMessagingService;

    private final ProgrammingTriggerService programmingTriggerService;

    private final LocalCIProgrammingLanguageFeatureService localCIProgrammingLanguageFeatureService;

    @Value("${artemis.version-control.url}")
    private URL localVCBaseUrl;

    @Value("${artemis.version-control.local-vcs-repo-path}")
    private String localVCBasePath;

    /**
     * Name of the header containing the authorization information.
     */
    public static final String AUTHORIZATION_HEADER = "Authorization";

    // Cache the retrieved repositories for quicker access.
    // The resolveRepository method is called multiple times per request.
    private final Map<String, Repository> repositories = new HashMap<>();

    public LocalVCServletService(AuthenticationManagerBuilder authenticationManagerBuilder, UserRepository userRepository,
            ProgrammingExerciseRepository programmingExerciseRepository, RepositoryAccessService repositoryAccessService, AuthorizationCheckService authorizationCheckService,
            ProgrammingExerciseParticipationService programmingExerciseParticipationService, AuxiliaryRepositoryService auxiliaryRepositoryService,
            LocalCITriggerService localCITriggerService, ProgrammingSubmissionService programmingSubmissionService, ProgrammingMessagingService programmingMessagingService,
            ProgrammingTriggerService programmingTriggerService, LocalCIProgrammingLanguageFeatureService localCIProgrammingLanguageFeatureService) {
        this.authenticationManagerBuilder = authenticationManagerBuilder;
        this.userRepository = userRepository;
        this.programmingExerciseRepository = programmingExerciseRepository;
        this.repositoryAccessService = repositoryAccessService;
        this.authorizationCheckService = authorizationCheckService;
        this.programmingExerciseParticipationService = programmingExerciseParticipationService;
        this.auxiliaryRepositoryService = auxiliaryRepositoryService;
        this.localCITriggerService = localCITriggerService;
        this.programmingSubmissionService = programmingSubmissionService;
        this.programmingMessagingService = programmingMessagingService;
        this.programmingTriggerService = programmingTriggerService;
        this.localCIProgrammingLanguageFeatureService = localCIProgrammingLanguageFeatureService;
    }

    /**
     *
     * @param repositoryPath the path of the repository, as parsed out of the URL (everything after /git).
     * @return the opened repository instance.
     * @throws RepositoryNotFoundException if the repository could not be found.
     */
    public Repository resolveRepository(String repositoryPath) throws RepositoryNotFoundException {
        // Find the local repository depending on the name.
        Path repositoryDir = Paths.get(localVCBasePath, repositoryPath);

        log.debug("Path to resolve repository from: {}", repositoryDir);
        if (!Files.exists(repositoryDir)) {
            log.info("Could not find local repository with name {}", repositoryPath);
            throw new RepositoryNotFoundException(repositoryPath);
        }

        if (repositories.containsKey(repositoryPath)) {
            log.debug("Retrieving cached local repository {}", repositoryPath);
            Repository repository = repositories.get(repositoryPath);
            repository.incrementOpen();
            return repository;
        }
        else {
            log.debug("Opening local repository {}", repositoryPath);
            try (Repository repository = FileRepositoryBuilder.create(repositoryDir.toFile())) {
                // Enable pushing without credentials, authentication is handled by the LocalVCPushFilter.
                repository.getConfig().setBoolean("http", null, "receivepack", true);

                this.repositories.put(repositoryPath, repository);
                repository.incrementOpen();
                return repository;
            }
            catch (IOException e) {
                log.error("Unable to open local repository {}", repositoryPath);
                throw new RepositoryNotFoundException(repositoryPath, e);
            }
        }
    }

    /**
     * Determines whether a given request to access a local VC repository (either via fetch of push) is authenticated and authorized.
     *
     * @param servletRequest       The object containing all information about the incoming request.
     * @param repositoryActionType Indicates whether the method should authenticate a fetch or a push request. For a push request, additional checks are conducted.
     * @throws LocalVCAuthException      If the user authentication fails or the user is not authorized to access a certain repository.
     * @throws LocalVCForbiddenException If the user is not allowed to access the repository, e.g. because offline IDE usage is not allowed or the due date has passed.
     * @throws LocalVCInternalException  If an internal error occurs, e.g. because the LocalVCRepositoryUrl could not be created.
     */
    public void authenticateAndAuthorizeGitRequest(HttpServletRequest servletRequest, RepositoryActionType repositoryActionType)
            throws LocalVCAuthException, LocalVCForbiddenException {

        long timeNanoStart = System.nanoTime();

        User user = authenticateUser(servletRequest.getHeader(LocalVCServletService.AUTHORIZATION_HEADER));

        // Optimization.
        // For each git command (i.e. 'git fetch' or 'git push'), the git client sends three requests.
        // The URLs of the first two requests end on '[repository URL]/info/refs'. The third one ends on '[repository URL]/git-receive-pack' (for push) and '[repository
        // URL]/git-upload-pack' (for fetch).
        // The following checks will only be conducted for the second request, so we do not have to access the database too often.
        // The first request does not contain credentials and will thus already be blocked by the 'authenticateUser' method above.
        if (!servletRequest.getRequestURI().endsWith("/info/refs")) {
            return;
        }

        LocalVCRepositoryUrl localVCRepositoryUrl = new LocalVCRepositoryUrl(servletRequest.getRequestURL().toString().replace("/info/refs", ""), localVCBaseUrl);

        String projectKey = localVCRepositoryUrl.getProjectKey();
        String repositoryTypeOrUserName = localVCRepositoryUrl.getRepositoryTypeOrUserName();

        ProgrammingExercise exercise;

        try {
            exercise = programmingExerciseRepository.findOneByProjectKeyOrThrow(projectKey, true);
        }
        catch (EntityNotFoundException e) {
            throw new LocalVCInternalException("Could not find single programming exercise with project key " + projectKey, e);
        }

        // Check that offline IDE usage is allowed.
        if (Boolean.FALSE.equals(exercise.isAllowOfflineIde()) && authorizationCheckService.isOnlyStudentInCourse(exercise.getCourseViaExerciseGroupOrCourseMember(), user)) {
            throw new LocalVCForbiddenException();
        }

        authorizeUser(repositoryTypeOrUserName, user, exercise, repositoryActionType, localVCRepositoryUrl.isPracticeRepository());

        log.info("Authorizing user {} for repository {} took {}", user.getLogin(), localVCRepositoryUrl, TimeLogUtil.formatDurationFrom(timeNanoStart));
    }

    private User authenticateUser(String authorizationHeader) throws LocalVCAuthException {

        String basicAuthCredentials = checkAuthorizationHeader(authorizationHeader);

        if (basicAuthCredentials.split(":").length != 2) {
            throw new LocalVCAuthException();
        }

        String username = basicAuthCredentials.split(":")[0];
        String password = basicAuthCredentials.split(":")[1];

        try {
            SecurityUtils.checkUsernameAndPasswordValidity(username, password);

            // Try to authenticate the user.
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
            authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        }
        catch (AccessForbiddenException | AuthenticationException e) {
            throw new LocalVCAuthException(e);
        }

        // Check that the user exists.
        return userRepository.findOneByLogin(username).orElseThrow(LocalVCAuthException::new);
    }

    private String checkAuthorizationHeader(String authorizationHeader) throws LocalVCAuthException {
        if (authorizationHeader == null) {
            throw new LocalVCAuthException();
        }

        String[] basicAuthCredentialsEncoded = authorizationHeader.split(" ");

        if (!("Basic".equals(basicAuthCredentialsEncoded[0]))) {
            throw new LocalVCAuthException();
        }

        // Return decoded basic auth credentials which contain the username and the password.
        return new String(Base64.getDecoder().decode(basicAuthCredentialsEncoded[1]));
    }

    private void authorizeUser(String repositoryTypeOrUserName, User user, ProgrammingExercise exercise, RepositoryActionType repositoryActionType, boolean isPracticeRepository)
            throws LocalVCAuthException, LocalVCForbiddenException {

        if (repositoryTypeOrUserName.equals(RepositoryType.TESTS.toString()) || auxiliaryRepositoryService.isAuxiliaryRepositoryOfExercise(repositoryTypeOrUserName, exercise)) {
            // Test and auxiliary repositories are only accessible by instructors and higher.
            try {
                repositoryAccessService.checkAccessTestOrAuxRepositoryElseThrow(repositoryActionType == RepositoryActionType.WRITE, exercise, user, repositoryTypeOrUserName);
            }
            catch (AccessForbiddenException e) {
                throw new LocalVCAuthException(e);
            }
            return;
        }

        ProgrammingExerciseParticipation participation;
        try {
            participation = programmingExerciseParticipationService.getParticipationForRepository(exercise, repositoryTypeOrUserName, isPracticeRepository, false);
        }
        catch (EntityNotFoundException e) {
            throw new LocalVCInternalException(
                    "No participation found for repository with repository type or username " + repositoryTypeOrUserName + " in exercise " + exercise.getId(), e);
        }

        try {
            repositoryAccessService.checkAccessRepositoryElseThrow(participation, user, exercise, repositoryActionType);
        }
        catch (AccessUnauthorizedException e) {
            throw new LocalVCAuthException(e);
        }
        catch (AccessForbiddenException e) {
            throw new LocalVCForbiddenException(e);
        }
    }

    /**
     * Returns the HTTP status code for the given exception thrown by the above method "authenticateAndAuthorizeGitRequest".
     *
     * @param exception     The exception thrown.
     * @param repositoryUrl The URL of the repository that was accessed.
     * @return The HTTP status code.
     */
    public int getHttpStatusForException(Exception exception, String repositoryUrl) {
        if (exception instanceof LocalVCAuthException) {
            return HttpStatus.UNAUTHORIZED.value();
        }
        else if (exception instanceof LocalVCForbiddenException) {
            return HttpStatus.FORBIDDEN.value();
        }
        else {
            log.error("Internal server error while trying to access repository {}: {}", repositoryUrl, exception.getMessage());
            return HttpStatus.INTERNAL_SERVER_ERROR.value();
        }
    }

    /**
     * Create a submission, trigger the respective build, and process the results.
     *
     * @param commitHash the hash of the last commit.
     * @param repository the remote repository which was pushed to.
     * @throws LocalCIException        if something goes wrong preparing the queueing of the build job.
     * @throws VersionControlException if the commit belongs to the wrong branch (i.e. not the default branch of the participation).
     */
    public void processNewPush(String commitHash, Repository repository) {
        long timeNanoStart = System.nanoTime();

        Path repositoryFolderPath = repository.getDirectory().toPath();

        LocalVCRepositoryUrl localVCRepositoryUrl = getLocalVCRepositoryUrl(repositoryFolderPath);

        String repositoryTypeOrUserName = localVCRepositoryUrl.getRepositoryTypeOrUserName();
        String projectKey = localVCRepositoryUrl.getProjectKey();

        ProgrammingExercise exercise;

        try {
            exercise = programmingExerciseRepository.findOneByProjectKeyOrThrow(projectKey, false);
        }
        catch (EntityNotFoundException e) {
            throw new LocalCIException("Could not find programming exercise for project key " + projectKey, e);
        }

        ProgrammingLanguage programmingLanguage = exercise.getProgrammingLanguage();
        ProjectType projectType = exercise.getProjectType();

        List<ProjectType> supportedProjectTypes = localCIProgrammingLanguageFeatureService.getProgrammingLanguageFeatures(programmingLanguage).projectTypes();

        if (projectType != null && !supportedProjectTypes.contains(exercise.getProjectType())) {
            throw new LocalCIException("The project type " + exercise.getProjectType() + " is not supported by the local CI.");
        }

        ProgrammingExerciseParticipation participation;

        try {
            participation = programmingExerciseParticipationService.getParticipationForRepository(exercise, repositoryTypeOrUserName, localVCRepositoryUrl.isPracticeRepository(),
                    true);
        }
        catch (EntityNotFoundException e) {
            throw new LocalCIException("Could not find participation for repository " + repositoryTypeOrUserName + " of exercise " + exercise, e);
        }

        try {
            if (commitHash == null) {
                commitHash = getLatestCommitHash(repository);
            }

            if (repositoryTypeOrUserName.equals(RepositoryType.TESTS.getName())) {
                processNewPushToTestRepository(exercise, commitHash, (SolutionProgrammingExerciseParticipation) participation);
                return;
            }

            Commit commit = extractCommitInfo(commitHash, repository);

            // Process push to any repository other than the test repository.
            processNewPushToRepository(participation, commit);
        }
        catch (GitAPIException | IOException e) {
            // This catch clause does not catch exceptions that happen during runBuildJob() as that method is called asynchronously.
            // For exceptions happening inside runBuildJob(), the user is notified. See the addBuildJobToQueue() method in the LocalCIBuildJobManagementService for that.
            throw new LocalCIException("Could not process new push to repository " + localVCRepositoryUrl.getURI() + " and commit " + commitHash + ". No build job was queued.", e);
        }

        log.info("New push processed to repository {} for commit {} in {}. A build job was queued.", localVCRepositoryUrl.getURI(), commitHash,
                TimeLogUtil.formatDurationFrom(timeNanoStart));
    }

    private LocalVCRepositoryUrl getLocalVCRepositoryUrl(Path repositoryFolderPath) {
        try {
            return new LocalVCRepositoryUrl(repositoryFolderPath, localVCBaseUrl);
        }
        catch (LocalVCInternalException e) {
            // This means something is misconfigured.
            throw new LocalCIException("Could not create valid repository URL from path " + repositoryFolderPath, e);
        }
    }

    private String getLatestCommitHash(Repository repository) throws GitAPIException {
        try (Git git = new Git(repository)) {
            RevCommit latestCommit = git.log().setMaxCount(1).call().iterator().next();
            return latestCommit.getName();
        }
    }

    /**
     * Process a new push to the test repository.
     * Build and test the solution repository to make sure all tests are still passing.
     *
     * @param exercise   the exercise for which the push was made.
     * @param commitHash the hash of the last commit to the test repository.
     * @throws LocalCIException if something unexpected goes wrong when creating the submission or triggering the build.
     */
    private void processNewPushToTestRepository(ProgrammingExercise exercise, String commitHash, SolutionProgrammingExerciseParticipation solutionParticipation) {
        // Create a new submission for the solution repository.
        ProgrammingSubmission submission;
        try {
            submission = programmingSubmissionService.createSolutionParticipationSubmissionWithTypeTest(exercise.getId(), commitHash);
        }
        catch (EntityNotFoundException | IllegalStateException e) {
            throw new LocalCIException("Could not create submission for solution participation", e);
        }

        programmingMessagingService.notifyUserAboutSubmission(submission, exercise.getId());

        try {
            // Set a flag to inform the instructor that the student results are now outdated.
            programmingTriggerService.setTestCasesChanged(exercise.getId(), true);
        }
        catch (EntityNotFoundException e) {
            throw new LocalCIException("Could not set test cases changed flag", e);
        }

        localCITriggerService.triggerBuild(solutionParticipation, commitHash);

        try {
            programmingTriggerService.triggerTemplateBuildAndNotifyUser(exercise.getId(), submission.getCommitHash(), SubmissionType.TEST);
        }
        catch (EntityNotFoundException e) {
            // Something went wrong while retrieving the template participation.
            // At this point, programmingMessagingService.notifyUserAboutSubmissionError() does not work, because the template participation is not available.
            // The instructor will see in the UI that no build of the template repository was conducted and will receive an error message when triggering the build manually.
            log.error("Something went wrong while triggering the template build for exercise " + exercise.getId() + " after the solution build was finished.", e);
        }
    }

    /**
     * Process a new push to a student's repository or to the template or solution repository of the exercise.
     *
     * @param participation the participation for which the push was made
     * @param commit        the commit that was pushed
     * @throws LocalCIException        if something unexpected goes wrong creating the submission or triggering the build
     * @throws VersionControlException if the commit belongs to the wrong branch (i.e. not the default branch of the participation)
     */
    private void processNewPushToRepository(ProgrammingExerciseParticipation participation, Commit commit) {
        // The 'user' is not properly logged into Artemis, this leads to an issue when accessing custom repository methods.
        // Therefore, a mock auth object has to be created.
        SecurityUtils.setAuthorizationObject();
        ProgrammingSubmission submission;
        try {
            submission = programmingSubmissionService.processNewProgrammingSubmission(participation, commit);
        }
        catch (EntityNotFoundException | IllegalStateException | IllegalArgumentException e) {
            throw new LocalCIException("Could not process submission for participation: " + e.getMessage(), e);
        }

        // Remove unnecessary information from the new submission.
        submission.getParticipation().setSubmissions(null);
        programmingMessagingService.notifyUserAboutSubmission(submission, participation.getExercise().getId());
    }

    private Commit extractCommitInfo(String commitHash, Repository repository) throws IOException, GitAPIException {
        RevCommit revCommit;
        String branch = null;

        ObjectId objectId = repository.resolve(commitHash);

        if (objectId == null) {
            throw new LocalCIException("Could not resolve commit hash " + commitHash + " in repository");
        }

        revCommit = repository.parseCommit(objectId);

        // Get the branch name.
        Git git = new Git(repository);
        // Look in the 'refs/heads' namespace for a ref that points to the commit.
        // The returned map contains at most one entry where the key is the commit id and the value denotes the branch which points to it.
        Map<ObjectId, String> objectIdBranchNameMap = git.nameRev().addPrefix("refs/heads").add(objectId).call();
        if (!objectIdBranchNameMap.isEmpty()) {
            branch = objectIdBranchNameMap.get(objectId);
        }
        git.close();

        if (revCommit == null || branch == null) {
            throw new LocalCIException("Something went wrong retrieving the revCommit or the branch.");
        }

        Commit commit = new Commit();
        commit.setCommitHash(commitHash);
        commit.setAuthorName(revCommit.getAuthorIdent().getName());
        commit.setAuthorEmail(revCommit.getAuthorIdent().getEmailAddress());
        commit.setBranch(branch);
        commit.setMessage(revCommit.getFullMessage());

        return commit;
    }
}
