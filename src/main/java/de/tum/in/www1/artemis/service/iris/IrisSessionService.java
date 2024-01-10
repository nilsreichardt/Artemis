package de.tum.in.www1.artemis.service.iris;

import javax.ws.rs.BadRequestException;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import de.tum.in.www1.artemis.domain.User;
import de.tum.in.www1.artemis.domain.iris.message.IrisMessage;
import de.tum.in.www1.artemis.domain.iris.session.*;
import de.tum.in.www1.artemis.repository.UserRepository;
import de.tum.in.www1.artemis.service.iris.session.*;

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

    public IrisSessionService(UserRepository userRepository, IrisChatSessionService irisChatSessionService, IrisHestiaSessionService irisHestiaSessionService,
            IrisCodeEditorSessionService irisCodeEditorSessionService) {
        this.userRepository = userRepository;
        this.irisChatSessionService = irisChatSessionService;
        this.irisHestiaSessionService = irisHestiaSessionService;
        this.irisCodeEditorSessionService = irisCodeEditorSessionService;
    }

    /**
     * Checks if the exercise connected to the session has Iris activated
     *
     * @param session the session to check for
     */
    public void checkIsIrisActivated(IrisSession session) {
        var wrapper = getIrisSessionSubService(session);
        wrapper.irisSubFeatureInterface.checkIsFeatureActivatedFor(wrapper.irisSession);
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
        var wrapper = getIrisSessionSubService(session);
        wrapper.irisSubFeatureInterface.checkHasAccessTo(user, wrapper.irisSession);
    }

    /**
     * Sends a request to Iris to get a message for the given session.
     * It decides which Iris subsystem should handle it based on the session type.
     * Currently, only the chat subsystem exists.
     *
     * @param session The session to get a message for
     */
    public void requestMessageFromIris(IrisSession session) {
        var wrapper = getIrisSessionSubService(session);
        if (wrapper.irisSubFeatureInterface instanceof IrisChatBasedFeatureInterface) {
            ((IrisChatBasedFeatureInterface<?>) wrapper.irisSubFeatureInterface).requestAndHandleResponse(wrapper.irisSession);
        }
        else {
            throw new BadRequestException("Invalid Iris session type " + session.getClass().getSimpleName());
        }
    }

    public void sendOverWebsocket(IrisMessage message) {
        var wrapper = getIrisSessionSubService(message.getSession());
        if (wrapper.irisSubFeatureInterface instanceof IrisChatBasedFeatureInterface) {
            ((IrisChatBasedFeatureInterface<?>) wrapper.irisSubFeatureInterface).sendOverWebsocket(message);
        }
        else {
            throw new BadRequestException("Invalid Iris session type " + message.getSession().getClass().getSimpleName());
        }
    }

    public void checkRateLimit(IrisSession session, User user) {
        var wrapper = getIrisSessionSubService(session);
        if (wrapper.irisSubFeatureInterface instanceof IrisRateLimitedFeatureInterface) {
            ((IrisRateLimitedFeatureInterface) wrapper.irisSubFeatureInterface).checkRateLimit(user);
        }
    }

    @SuppressWarnings("unchecked")
    private <S extends IrisSession> IrisSubFeatureWrapper<S> getIrisSessionSubService(S session) {
        if (session instanceof IrisChatSession) {
            return (IrisSubFeatureWrapper<S>) new IrisSubFeatureWrapper<>(irisChatSessionService, castToSessionType(session, IrisChatSession.class));
        }
        if (session instanceof IrisHestiaSession) {
            return (IrisSubFeatureWrapper<S>) new IrisSubFeatureWrapper<>(irisHestiaSessionService, castToSessionType(session, IrisHestiaSession.class));
        }
        if (session instanceof IrisCodeEditorSession) {
            return (IrisSubFeatureWrapper<S>) new IrisSubFeatureWrapper<>(irisCodeEditorSessionService, castToSessionType(session, IrisCodeEditorSession.class));
        }
        throw new BadRequestException("Unknown Iris session type " + session.getClass().getSimpleName());
    }

    /**
     * Helper method to cast an IrisSession to a specific type.
     * Throws an IllegalStateException if the session is not of the given type.
     *
     * @param irisSession  The session to cast
     * @param sessionClass The class to cast to
     * @param <S>          The type of the session
     * @return The casted session
     */
    private <S extends IrisSession> S castToSessionType(IrisSession irisSession, Class<S> sessionClass) {
        if (!sessionClass.isInstance(irisSession)) {
            throw new IllegalStateException("IrisSession is not of type " + sessionClass.getSimpleName());
        }
        return sessionClass.cast(irisSession);
    }

    private record IrisSubFeatureWrapper<S extends IrisSession>(IrisSubFeatureInterface<S> irisSubFeatureInterface, S irisSession) {
    }
}
