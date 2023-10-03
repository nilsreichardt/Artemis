package de.tum.in.www1.artemis.service.iris;

import javax.ws.rs.BadRequestException;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import de.tum.in.www1.artemis.domain.ProgrammingExercise;
import de.tum.in.www1.artemis.domain.User;
import de.tum.in.www1.artemis.domain.iris.session.IrisChatSession;
import de.tum.in.www1.artemis.domain.iris.session.IrisCodeEditorSession;
import de.tum.in.www1.artemis.domain.iris.session.IrisHestiaSession;
import de.tum.in.www1.artemis.domain.iris.session.IrisSession;
import de.tum.in.www1.artemis.repository.UserRepository;
import de.tum.in.www1.artemis.repository.iris.IrisChatSessionRepository;
import de.tum.in.www1.artemis.repository.iris.IrisCodeEditorSessionRepository;
import de.tum.in.www1.artemis.service.iris.session.IrisChatSessionService;
import de.tum.in.www1.artemis.service.iris.session.IrisCodeEditorSessionService;
import de.tum.in.www1.artemis.service.iris.session.IrisHestiaSessionService;
import de.tum.in.www1.artemis.service.iris.session.IrisSessionSubServiceInterface;

/**
 * Service for managing Iris sessions.
 */
@Service
@Profile("iris")
public class IrisSessionService {

    private final UserRepository userRepository;

    private final IrisChatSessionService irisChatSessionService;

    private final IrisHestiaSessionService irisHestiaSessionService;

    private final IrisCodeEditorSessionService irisCodeEditorSessionService;

    private final IrisChatSessionRepository irisChatSessionRepository;

    private final IrisCodeEditorSessionRepository irisCodeEditorSessionRepository;

    public IrisSessionService(UserRepository userRepository, IrisChatSessionService irisChatSessionService, IrisHestiaSessionService irisHestiaSessionService,
            IrisCodeEditorSessionService irisCodeEditorSessionService, IrisChatSessionRepository irisChatSessionRepository,
            IrisCodeEditorSessionRepository irisCodeEditorSessionRepository) {
        this.userRepository = userRepository;
        this.irisChatSessionService = irisChatSessionService;
        this.irisHestiaSessionService = irisHestiaSessionService;
        this.irisCodeEditorSessionService = irisCodeEditorSessionService;
        this.irisChatSessionRepository = irisChatSessionRepository;
        this.irisCodeEditorSessionRepository = irisCodeEditorSessionRepository;
    }

    /**
     * Creates a new Iris session for the given exercise and user.
     *
     * @param exercise The exercise the session belongs to
     * @param user     The user the session belongs to
     * @return The created session
     */
    public IrisChatSession createChatSessionForProgrammingExercise(ProgrammingExercise exercise, User user) {
        return irisChatSessionRepository.save(new IrisChatSession(exercise, user));
    }

    public IrisCodeEditorSession createCodeEditorSession(ProgrammingExercise exercise, User user) {
        return irisCodeEditorSessionRepository.save(new IrisCodeEditorSession(exercise, user));
    }

    /**
     * Checks if the exercise connected to the session has Iris activated
     *
     * @param session the session to check for
     */
    public void checkIsIrisActivated(IrisSession session) {
        getIrisSessionSubService(session).checkIsIrisActivated(session);
    }

    /**
     * Checks if the user has access to the Iris session.
     * If the user is null, the user is fetched from the database.
     *
     * @param session The session to check
     * @param user    The user to check
     */
    public void checkHasAccessToIrisSession(IrisSession session, User user) {
        if (user == null) {
            user = userRepository.getUserWithGroupsAndAuthorities();
        }
        getIrisSessionSubService(session).checkHasAccessToIrisSession(session, user);
    }

    /**
     * Sends a request to Iris to get a message for the given session.
     * It decides which Iris subsystem should handle it based on the session type.
     * Currently, only the chat subsystem exists.
     *
     * @param session The session to get a message for
     */
    public void requestMessageFromIris(IrisSession session) {
        getIrisSessionSubService(session).requestAndHandleResponse(session);
    }

    private IrisSessionSubServiceInterface getIrisSessionSubService(IrisSession session) {
        if (session instanceof IrisChatSession) {
            return irisChatSessionService;
        }
        if (session instanceof IrisHestiaSession) {
            return irisHestiaSessionService;
        }
        if (session instanceof IrisCodeEditorSession) {
            return irisCodeEditorSessionService;
        }
        throw new BadRequestException("Unknown Iris session type " + session.getClass().getSimpleName());
    }
}
