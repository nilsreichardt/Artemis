package de.tum.in.www1.artemis.service.iris.session;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.*;

import javax.ws.rs.BadRequestException;

import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.errors.GitAPIException;
import org.eclipse.jgit.treewalk.FileTreeIterator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import de.tum.in.www1.artemis.domain.*;
import de.tum.in.www1.artemis.domain.iris.message.IrisMessage;
import de.tum.in.www1.artemis.domain.iris.message.IrisMessageSender;
import de.tum.in.www1.artemis.domain.iris.session.IrisChatSession;
import de.tum.in.www1.artemis.domain.iris.session.IrisSession;
import de.tum.in.www1.artemis.domain.iris.settings.IrisSubSettingsType;
import de.tum.in.www1.artemis.domain.participation.ProgrammingExerciseStudentParticipation;
import de.tum.in.www1.artemis.repository.ProgrammingExerciseStudentParticipationRepository;
import de.tum.in.www1.artemis.repository.ProgrammingSubmissionRepository;
import de.tum.in.www1.artemis.repository.TemplateProgrammingExerciseParticipationRepository;
import de.tum.in.www1.artemis.repository.iris.IrisSessionRepository;
import de.tum.in.www1.artemis.security.Role;
import de.tum.in.www1.artemis.service.AuthorizationCheckService;
import de.tum.in.www1.artemis.service.RepositoryService;
import de.tum.in.www1.artemis.service.connectors.GitService;
import de.tum.in.www1.artemis.service.connectors.iris.IrisConnectorService;
import de.tum.in.www1.artemis.service.iris.IrisMessageService;
import de.tum.in.www1.artemis.service.iris.IrisRateLimitService;
import de.tum.in.www1.artemis.service.iris.exception.IrisNoResponseException;
import de.tum.in.www1.artemis.service.iris.settings.IrisSettingsService;
import de.tum.in.www1.artemis.service.iris.websocket.IrisChatWebsocketService;
import de.tum.in.www1.artemis.web.rest.errors.AccessForbiddenException;
import de.tum.in.www1.artemis.web.rest.errors.ConflictException;
import de.tum.in.www1.artemis.web.rest.errors.InternalServerErrorException;

/**
 * Service to handle the chat subsystem of Iris.
 */
@Service
@Profile("iris")
public class IrisChatSessionService implements IrisChatBasedFeatureInterface<IrisChatSession>, IrisRateLimitedFeatureInterface {

    private static final Logger log = LoggerFactory.getLogger(IrisChatSessionService.class);

    private final IrisConnectorService irisConnectorService;

    private final IrisMessageService irisMessageService;

    private final IrisSettingsService irisSettingsService;

    private final IrisChatWebsocketService irisChatWebsocketService;

    private final AuthorizationCheckService authCheckService;

    private final IrisSessionRepository irisSessionRepository;

    private final GitService gitService;

    private final RepositoryService repositoryService;

    private final TemplateProgrammingExerciseParticipationRepository templateProgrammingExerciseParticipationRepository;

    private final ProgrammingExerciseStudentParticipationRepository programmingExerciseStudentParticipationRepository;

    private final ProgrammingSubmissionRepository programmingSubmissionRepository;

    private final IrisRateLimitService rateLimitService;

    public IrisChatSessionService(IrisConnectorService irisConnectorService, IrisMessageService irisMessageService, IrisSettingsService irisSettingsService,
            IrisChatWebsocketService irisChatWebsocketService, AuthorizationCheckService authCheckService, IrisSessionRepository irisSessionRepository, GitService gitService,
            RepositoryService repositoryService, TemplateProgrammingExerciseParticipationRepository templateProgrammingExerciseParticipationRepository,
            ProgrammingExerciseStudentParticipationRepository programmingExerciseStudentParticipationRepository, ProgrammingSubmissionRepository programmingSubmissionRepository,
            IrisRateLimitService rateLimitService) {
        this.irisConnectorService = irisConnectorService;
        this.irisMessageService = irisMessageService;
        this.irisSettingsService = irisSettingsService;
        this.irisChatWebsocketService = irisChatWebsocketService;
        this.authCheckService = authCheckService;
        this.irisSessionRepository = irisSessionRepository;
        this.gitService = gitService;
        this.repositoryService = repositoryService;
        this.templateProgrammingExerciseParticipationRepository = templateProgrammingExerciseParticipationRepository;
        this.programmingExerciseStudentParticipationRepository = programmingExerciseStudentParticipationRepository;
        this.programmingSubmissionRepository = programmingSubmissionRepository;
        this.rateLimitService = rateLimitService;
    }

    /**
     * Creates a new Iris session for the given exercise and user.
     *
     * @param exercise The exercise the session belongs to
     * @param user     The user the session belongs to
     * @return The created session
     */
    public IrisChatSession createChatSessionForProgrammingExercise(ProgrammingExercise exercise, User user) {
        if (exercise.isExamExercise()) {
            throw new ConflictException("Iris is not supported for exam exercises", "Iris", "irisExamExercise");
        }
        return irisSessionRepository.save(new IrisChatSession(exercise, user));
    }

    /**
     * Checks if the user has access to the Iris session.
     * A user has access if they have access to the exercise and the session belongs to them.
     * If the user is null, the user is fetched from the database.
     *
     * @param user    The user to check
     * @param session The session to check
     */
    @Override
    public void checkHasAccessTo(User user, IrisChatSession session) {
        authCheckService.checkHasAtLeastRoleForExerciseElseThrow(Role.STUDENT, session.getExercise(), user);
        if (!Objects.equals(session.getUser(), user)) {
            throw new AccessForbiddenException("Iris Session", session.getId());
        }
    }

    /**
     * Checks if the exercise connected to IrisChatSession has Iris enabled
     *
     * @param session The session to check
     */
    @Override
    public void checkIsFeatureActivatedFor(IrisChatSession session) {
        irisSettingsService.isEnabledForElseThrow(IrisSubSettingsType.CHAT, session.getExercise());
    }

    @Override
    public void sendOverWebsocket(IrisMessage message) {
        irisChatWebsocketService.sendMessage(message);
    }

    @Override
    public void checkRateLimit(User user) {
        rateLimitService.checkRateLimitElseThrow(user);
    }

    /**
     * Sends all messages of the session to an LLM and handles the response by saving the message
     * and sending it to the student via the Websocket.
     *
     * @param session The chat session to send to the LLM
     */
    @Override
    public void requestAndHandleResponse(IrisSession session) {
        var fullSession = irisSessionRepository.findByIdWithMessagesAndContents(session.getId());
        Map<String, Object> parameters = new HashMap<>();
        if (!(fullSession instanceof IrisChatSession chatSession)) {
            throw new BadRequestException("Trying to get Iris response for session " + session.getId() + " without exercise");
        }
        if (chatSession.getExercise().isExamExercise()) {
            throw new ConflictException("Iris is not supported for exam exercises", "Iris", "irisExamExercise");
        }
        var exercise = chatSession.getExercise();
        parameters.put("exercise", exercise);
        parameters.put("course", exercise.getCourseViaExerciseGroupOrCourseMember());
        parameters.put("latestSubmission", "");
        parameters.put("buildFailed", "");
        parameters.put("buildLog", "");
        var participations = programmingExerciseStudentParticipationRepository.findAllWithSubmissionsByExerciseIdAndStudentLogin(exercise.getId(),
                chatSession.getUser().getLogin());
        if (!participations.isEmpty()) {
            var participation = participations.get(participations.size() - 1);
            var submission = participation.getSubmissions().stream().max(Submission::compareTo);
            Optional<ProgrammingSubmission> latestSubmission = Optional.empty();
            if (submission.isPresent()) {
                latestSubmission = programmingSubmissionRepository.findWithEagerBuildLogEntriesById(submission.get().getId());
            }
            if (latestSubmission.isPresent()) {
                parameters.put("latestSubmission", latestSubmission.get());
                parameters.put("buildFailed", latestSubmission.get().isBuildFailed());
                parameters.put("buildLog", latestSubmission.get().getBuildLogEntries());
            }
        }
        parameters.put("session", chatSession);
        addDiffAndTemplatesForStudentAndExerciseIfPossible(exercise, participations, parameters);

        var irisSettings = irisSettingsService.getCombinedIrisSettingsFor(exercise, false);
        irisConnectorService.sendRequest(irisSettings.irisChatSettings().getTemplate(), irisSettings.irisChatSettings().getPreferredModel(), parameters)
                .handleAsync((irisMessage, throwable) -> {
                    if (throwable != null) {
                        log.error("Error while getting response from Iris model", throwable);
                        irisChatWebsocketService.sendException(chatSession, throwable.getCause());
                    }
                    else if (irisMessage != null) {
                        var irisMessageSaved = irisMessageService.saveMessage(irisMessage.message(), chatSession, IrisMessageSender.LLM);
                        irisChatWebsocketService.sendMessage(irisMessageSaved);
                    }
                    else {
                        log.error("No response from Iris model");
                        irisChatWebsocketService.sendException(chatSession, new IrisNoResponseException());
                    }
                    return null;
                });
    }

    private void addDiffAndTemplatesForStudentAndExerciseIfPossible(ProgrammingExercise exercise, List<ProgrammingExerciseStudentParticipation> studentParticipations,
            Map<String, Object> parameters) {
        parameters.put("gitDiff", "");
        parameters.put("studentRepository", Map.of());
        parameters.put("templateRepository", Map.of());

        var templateParticipation = templateProgrammingExerciseParticipationRepository.findByProgrammingExerciseId(exercise.getId());

        Repository templateRepo;
        Repository studentRepo;

        if (templateParticipation.isEmpty()) {
            throw new InternalServerErrorException("Iris cannot function without template participation");
        }
        if (studentParticipations.isEmpty()) {
            try {
                templateRepo = gitService.getOrCheckoutRepository(templateParticipation.get().getVcsRepositoryUri(), true);
            }
            catch (GitAPIException e) {
                throw new InternalServerErrorException("Iris cannot function without template participation");
            }
            parameters.put("templateRepository", repositoryService.getFilesWithContent(templateRepo));
            return;
        }

        try {
            templateRepo = gitService.getOrCheckoutRepository(templateParticipation.get().getVcsRepositoryUri(), true);
            studentRepo = gitService.getOrCheckoutRepository(studentParticipations.get(studentParticipations.size() - 1).getVcsRepositoryUri(), true);
        }
        catch (GitAPIException e) {
            throw new InternalServerErrorException("Could not fetch existing student or template participation");
        }
        parameters.put("templateRepository", repositoryService.getFilesWithContent(templateRepo));
        parameters.put("studentRepository", repositoryService.getFilesWithContent(studentRepo));

        var oldTreeParser = new FileTreeIterator(templateRepo);
        var newTreeParser = new FileTreeIterator(studentRepo);

        gitService.resetToOriginHead(templateRepo);
        gitService.pullIgnoreConflicts(templateRepo);
        gitService.resetToOriginHead(studentRepo);
        gitService.pullIgnoreConflicts(studentRepo);

        try (ByteArrayOutputStream diffOutputStream = new ByteArrayOutputStream(); Git git = Git.wrap(templateRepo)) {
            git.diff().setOldTree(oldTreeParser).setNewTree(newTreeParser).setOutputStream(diffOutputStream).call();
            parameters.put("gitDiff", diffOutputStream.toString());
        }
        catch (GitAPIException | IOException e) {
            throw new InternalServerErrorException("Could not generate diff from existing template and student participation");
        }
    }
}
