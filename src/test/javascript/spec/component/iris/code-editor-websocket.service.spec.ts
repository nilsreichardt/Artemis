import { TestBed, fakeAsync, flush, tick } from '@angular/core/testing';
import { HttpClientTestingModule } from '@angular/common/http/testing';
import { JhiWebsocketService } from 'app/core/websocket/websocket.service';
import { IrisStateStore } from 'app/iris/state-store.service';
import { IrisCodeEditorWebsocketService } from 'app/iris/code-editor-websocket.service';
import { MockProvider } from 'ng-mocks';
import { of } from 'rxjs';
import { AccountService } from 'app/core/auth/account.service';
import { MockAccountService } from '../../helpers/mocks/service/mock-account.service';
import { ActiveConversationMessageLoadedAction, ConversationErrorOccurredAction, SessionReceivedAction, StudentMessageSentAction } from 'app/iris/state-store.model';
import {
    mockCodeEditorWebsocketClientMessage,
    mockCodeEditorWebsocketKnownError,
    mockCodeEditorWebsocketServerMessage,
    mockCodeEditorWebsocketUnknownError,
    mockServerMessage,
} from '../../helpers/sample/iris-sample-data';
import { IrisErrorMessageKey } from 'app/entities/iris/iris-errors.model';
import { IrisUserMessage } from 'app/entities/iris/iris-message.model';

describe('IrisCodeEditorWebsocketService', () => {
    let irisWebsocketService: IrisCodeEditorWebsocketService;
    let jhiWebsocketService: JhiWebsocketService;
    let irisStateStore: IrisStateStore;

    const channel = '/user/topic/iris/code-editor-sessions/0';
    const newMessageObservable = of(mockCodeEditorWebsocketServerMessage);

    beforeEach(() => {
        TestBed.configureTestingModule({
            imports: [HttpClientTestingModule],
            providers: [IrisCodeEditorWebsocketService, MockProvider(JhiWebsocketService), IrisStateStore, { provide: AccountService, useClass: MockAccountService }],
        });
        irisWebsocketService = TestBed.inject(IrisCodeEditorWebsocketService);
        jhiWebsocketService = TestBed.inject(JhiWebsocketService);
        irisStateStore = TestBed.inject(IrisStateStore);
    });

    afterEach(() => {
        irisWebsocketService.ngOnDestroy();
        jest.restoreAllMocks();
    });

    it('should subscribe to a channel, get session updates and notify store about new messages', fakeAsync(() => {
        const websocketSubscribeSpy = jest.spyOn(jhiWebsocketService, 'subscribe');
        const websocketReceiveMock = jest.spyOn(jhiWebsocketService, 'receive').mockReturnValue(newMessageObservable);
        const dispatchSpy = jest.spyOn(irisStateStore, 'dispatch');

        irisStateStore.dispatch(new SessionReceivedAction(0, []));

        tick();

        expect(websocketSubscribeSpy).toHaveBeenCalledOnce();
        expect(websocketSubscribeSpy).toHaveBeenCalledWith(channel);

        expect(websocketReceiveMock).toHaveBeenCalledOnce();
        expect(websocketReceiveMock).toHaveBeenCalledWith(channel);

        expect(dispatchSpy).toHaveBeenCalledWith(new ActiveConversationMessageLoadedAction(mockServerMessage));
        expect(dispatchSpy).toHaveBeenCalledTimes(2);
    }));

    it('should unsubscribe from a channel', fakeAsync(() => {
        jest.spyOn(jhiWebsocketService, 'subscribe');
        jest.spyOn(jhiWebsocketService, 'unsubscribe');
        jest.spyOn(jhiWebsocketService, 'receive').mockReturnValue(newMessageObservable);
        irisStateStore.dispatch(new SessionReceivedAction(0, []));
        tick();
        irisStateStore.dispatch(new SessionReceivedAction(2, []));
        tick();
        expect(jhiWebsocketService.unsubscribe).toHaveBeenCalledWith(channel);
    }));

    it('should receive an unknown error type from the server and dispatch a technical error', fakeAsync(() => {
        const websocketReceiveMock = jest.spyOn(jhiWebsocketService, 'receive').mockReturnValue(of(mockCodeEditorWebsocketUnknownError));
        const dispatchSpy = jest.spyOn(irisStateStore, 'dispatch');

        irisStateStore.dispatch(new SessionReceivedAction(0, []));

        tick();

        expect(websocketReceiveMock).toHaveBeenCalledOnce();
        expect(websocketReceiveMock).toHaveBeenCalledWith(channel);

        expect(dispatchSpy).toHaveBeenCalledWith(new ConversationErrorOccurredAction(IrisErrorMessageKey.TECHNICAL_ERROR_RESPONSE));
        expect(dispatchSpy).toHaveBeenCalledTimes(2); // Include the existing dispatch count
    }));

    it('should receive a new server exception message and dispatch corresponding action', fakeAsync(() => {
        const websocketReceiveMock = jest.spyOn(jhiWebsocketService, 'receive').mockReturnValue(of(mockCodeEditorWebsocketKnownError));
        const dispatchSpy = jest.spyOn(irisStateStore, 'dispatch');

        irisStateStore.dispatch(new SessionReceivedAction(0, []));

        tick();

        expect(websocketReceiveMock).toHaveBeenCalledOnce();
        expect(websocketReceiveMock).toHaveBeenCalledWith(channel);

        const map = new Map<string, any>();
        map.set('model', 'gpt-4');

        expect(dispatchSpy).toHaveBeenCalledWith(new ConversationErrorOccurredAction(IrisErrorMessageKey.NO_MODEL_AVAILABLE, map));
        expect(dispatchSpy).toHaveBeenCalledTimes(2); // Include the existing dispatch count
    }));

    it('should receive a new server response message and add it to the store', fakeAsync(() => {
        const websocketReceiveMock = jest.spyOn(jhiWebsocketService, 'receive').mockReturnValue(of(mockCodeEditorWebsocketServerMessage));
        const dispatchSpy = jest.spyOn(irisStateStore, 'dispatch');

        irisStateStore.dispatch(new SessionReceivedAction(0, []));

        tick();

        expect(websocketReceiveMock).toHaveBeenCalledOnce();
        expect(websocketReceiveMock).toHaveBeenCalledWith(channel);

        expect(dispatchSpy).toHaveBeenNthCalledWith(2, new ActiveConversationMessageLoadedAction(mockCodeEditorWebsocketServerMessage.message!));
        expect(dispatchSpy).toHaveBeenCalledTimes(2);
        flush();
    }));

    it('should receive a new student message and emit an action', fakeAsync(() => {
        const websocketReceiveMock = jest.spyOn(jhiWebsocketService, 'receive').mockReturnValue(of(mockCodeEditorWebsocketClientMessage));
        const dispatchSpy = jest.spyOn(irisStateStore, 'dispatch');

        irisStateStore.dispatch(new SessionReceivedAction(0, []));

        tick();

        expect(websocketReceiveMock).toHaveBeenCalledOnce();
        expect(websocketReceiveMock).toHaveBeenCalledWith(channel);

        expect(dispatchSpy).toHaveBeenNthCalledWith(2, {
            ...new StudentMessageSentAction(
                mockCodeEditorWebsocketClientMessage.message as IrisUserMessage,
                setTimeout(() => {}),
            ),
            timeoutId: expect.any(Number),
        });
        flush();
    }));
});
