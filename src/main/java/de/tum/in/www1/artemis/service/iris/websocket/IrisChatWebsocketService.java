package de.tum.in.www1.artemis.service.iris.websocket;

import de.tum.in.www1.artemis.domain.iris.session.IrisChatSession;
import de.tum.in.www1.artemis.domain.iris.session.IrisSession;
import de.tum.in.www1.artemis.service.WebsocketMessagingService;
import de.tum.in.www1.artemis.service.iris.IrisWebsocketService;
import org.springframework.stereotype.Service;

@Service
public class IrisChatWebsocketService extends IrisWebsocketService {
    
    public IrisChatWebsocketService(WebsocketMessagingService websocketMessagingService) {
        // Might want to change topic to "chat-sessions" or something similar
        super(websocketMessagingService, "sessions");
    }
    
    @Override
    protected void checkSessionType(IrisSession irisSession) {
        if (!(irisSession instanceof IrisChatSession)) {
            throw new UnsupportedOperationException("Only IrisChatSession is supported");
        }
    }
    
    @Override
    protected String getUserLogin(IrisSession irisSession) {
        return ((IrisChatSession) irisSession).getUser().getLogin();
    }
    
}
