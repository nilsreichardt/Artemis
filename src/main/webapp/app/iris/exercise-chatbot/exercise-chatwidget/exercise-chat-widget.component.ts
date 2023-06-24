import { faArrowDown, faCircle, faCircleInfo, faCompress, faExpand, faPaperPlane, faRobot, faXmark } from '@fortawesome/free-solid-svg-icons';
import { ActivatedRoute } from '@angular/router';
import { LocalStorageService } from 'ngx-webstorage';
import { AccountService } from 'app/core/auth/account.service';
import { User } from 'app/core/user/user.model';
import { ButtonType } from 'app/shared/components/button.component';
import { AfterViewInit, Component, ElementRef, Inject, OnDestroy, OnInit, ViewChild } from '@angular/core';
import { MAT_DIALOG_DATA, MatDialog } from '@angular/material/dialog';
import { IrisStateStore } from 'app/iris/state-store.service';
import { ConversationErrorOccurredAction, NumNewMessagesResetAction, StudentMessageSentAction } from 'app/iris/state-store.model';
import { IrisHttpMessageService } from 'app/iris/http-message.service';
import { IrisClientMessage, IrisMessage, IrisSender } from 'app/entities/iris/iris-message.model';
import { IrisMessageContent, IrisMessageContentType } from 'app/entities/iris/iris-content-type.model';
import { Subscription } from 'rxjs';
import { ResizeSensor } from 'css-element-queries';

@Component({
    selector: 'jhi-exercise-chat-widget',
    templateUrl: './exercise-chat-widget.component.html',
    styleUrls: ['./exercise-chat-widget.component.scss'],
})
export class ExerciseChatWidgetComponent implements OnInit, OnDestroy, AfterViewInit {
    @ViewChild('chatWidget') chatWidget!: ElementRef;
    @ViewChild('chatBody') chatBody!: ElementRef;
    @ViewChild('scrollArrow') scrollArrow!: ElementRef;
    @ViewChild('messageTextarea', { static: false }) messageTextarea: ElementRef;
    @ViewChild('unreadMessage', { static: false }) unreadMessage!: ElementRef;

    readonly SENDER_USER = IrisSender.USER;
    readonly SENDER_SERVER = IrisSender.LLM;
    readonly stateStore: IrisStateStore;

    stateSubscription: Subscription;
    messages: IrisMessage[] = [];
    newMessageTextContent = '';
    isLoading: boolean;
    sessionId: number;
    numNewMessages = 0;
    unreadMessageIndex: number;
    error = '';
    dots = 1;

    userAccepted = false;
    isScrolledToBottom = true;
    rows = 1;
    showChatWidget = true;
    initialWidth = 330;
    initialHeight = 430;
    fullWidth = '95vw';
    fullHeight = '85vh';
    fullSize = localStorage.getItem('fullSize') === 'true';
    widgetWidth = localStorage.getItem('widgetWidth') || `${this.initialWidth}px`;
    widgetHeight = localStorage.getItem('widgetHeight') || `${this.initialHeight}px`;
    public ButtonType = ButtonType;

    constructor(
        private dialog: MatDialog,
        private route: ActivatedRoute,
        private localStorage: LocalStorageService,
        private accountService: AccountService,
        @Inject(MAT_DIALOG_DATA) public data: any,
        private httpMessageService: IrisHttpMessageService,
    ) {
        this.stateStore = data.stateStore;
    }

    // Icons
    faCircle = faCircle;
    faPaperPlane = faPaperPlane;
    faExpand = faExpand;
    faXmark = faXmark;
    faArrowDown = faArrowDown;
    faRobot = faRobot;
    faCircleInfo = faCircleInfo;
    faCompress = faCompress;

    ngOnInit() {
        this.accountService.identity().then((user: User) => {
            if (typeof user!.login === 'string') {
                this.userAccepted = localStorage.getItem(user!.login) == 'true';
            }
        });
        this.animateDots();
        this.stateSubscription = this.stateStore.getState().subscribe((state) => {
            this.messages = state.messages as IrisMessage[];
            this.isLoading = state.isLoading;
            this.error = state.error;
            this.sessionId = Number(state.sessionId);
            this.numNewMessages = state.numNewMessages;
        });
    }

    scrollToBottom(behavior: ScrollBehavior) {
        setTimeout(() => {
            const chatBodyElement: HTMLElement = this.chatBody.nativeElement;
            chatBodyElement.scrollTo({
                top: chatBodyElement.scrollHeight,
                behavior: behavior,
            });
        });
    }

    ngAfterViewInit() {
        console.log('hey');
        this.unreadMessageIndex = this.messages.length === 0 || this.numNewMessages === 0 ? -1 : this.messages.length - this.numNewMessages;
        if (this.numNewMessages > 0) {
            this.scrollToUnread();
        } else {
            this.scrollToBottom('auto');
        }

        const chatWidget: HTMLElement = this.chatWidget.nativeElement; // element you want to watch
        new ResizeSensor(chatWidget, () => {
            localStorage.setItem('widgetWidth', chatWidget.style.width);
            localStorage.setItem('widgetHeight', chatWidget.style.height);
        });
    }

    ngOnDestroy() {
        this.stateSubscription.unsubscribe();
    }

    animateDots() {
        setInterval(() => {
            this.dots = this.dots < 3 ? (this.dots += 1) : (this.dots = 1);
        }, 500);
    }

    onSend(): void {
        if (this.newMessageTextContent) {
            const message = this.newUserMessage(this.newMessageTextContent);
            this.stateStore
                .dispatchAndThen(new StudentMessageSentAction(message))
                .then(() => this.httpMessageService.createMessage(<number>this.sessionId, message).toPromise())
                .then(() => this.scrollToBottom('smooth'))
                .catch(() => this.stateStore.dispatch(new ConversationErrorOccurredAction('Something went wrong. Please try again later!')));
            this.newMessageTextContent = '';
        }
        this.scrollToBottom('smooth');
        this.resetChatBodyHeight();
    }

    scrollToUnread() {
        setTimeout(() => {
            const unreadMessageElement: HTMLElement = this.unreadMessage.nativeElement;
            unreadMessageElement.scrollIntoView({ behavior: 'auto' });
        });
    }

    closeChat() {
        this.stateStore.dispatch(new NumNewMessagesResetAction());
        this.dialog.closeAll();
    }

    acceptPermission() {
        this.accountService.identity().then((user: User) => {
            if (typeof user!.login === 'string') {
                localStorage.setItem(user!.login, 'true');
            }
        });

        this.userAccepted = true;
    }

    checkChatScroll() {
        const chatBody = this.chatBody.nativeElement;
        const scrollHeight = chatBody.scrollHeight;
        const scrollTop = chatBody.scrollTop;
        const clientHeight = chatBody.clientHeight;
        this.isScrolledToBottom = scrollHeight - scrollTop === clientHeight;
    }

    resetScreen(resetType: string) {
        setTimeout(() => {
            this.showChatWidget = false;
            this.widgetWidth = resetType == 'maximize' ? this.fullWidth : `${this.initialWidth}px`;
            this.widgetHeight = resetType == 'maximize' ? this.fullHeight : `${this.initialHeight}px`;
        }, 50);
        setTimeout(() => {
            this.scrollToBottom('auto');
        }, 100);
        setTimeout(() => {
            this.showChatWidget = true;
        }, 100);
    }

    maximizeScreen() {
        this.resetScreen('maximize');
        localStorage.setItem('widgetWidth', this.fullWidth);
        localStorage.setItem('widgetHeight', this.fullHeight);
        localStorage.setItem('fullSize', 'true');
        this.fullSize = true;
    }

    minimizeScreen() {
        this.resetScreen('minimize');
        localStorage.setItem('widgetWidth', `${this.initialWidth}px`);
        localStorage.setItem('widgetHeight', `${this.initialHeight}px`);
        localStorage.setItem('fullSize', 'false');
        this.fullSize = false;
    }

    handleKey(event: KeyboardEvent): void {
        if (event.key === 'Enter') {
            if (!event.shiftKey) {
                event.preventDefault();
                this.onSend();
            } else {
                const textArea = event.target as HTMLTextAreaElement;
                const { selectionStart, selectionEnd } = textArea;
                const value = textArea.value;
                textArea.value = value.slice(0, selectionStart) + value.slice(selectionEnd);
                textArea.selectionStart = textArea.selectionEnd = selectionStart + 1;
            }
        }
    }

    onRowChange() {
        const textarea: HTMLTextAreaElement = this.messageTextarea.nativeElement;
        const newRows = textarea.value.split('\n').length;
        if (newRows != this.rows) {
            if (newRows <= 3) {
                textarea.rows = newRows;
                this.adjustChatBodyHeight(newRows);
                this.rows = newRows;
            }
        }
    }

    adjustChatBodyHeight(newRows: number) {
        const textarea: HTMLTextAreaElement = this.messageTextarea.nativeElement;
        const chatBody: HTMLElement = this.chatBody.nativeElement;
        const scrollArrow: HTMLElement = this.scrollArrow.nativeElement;
        const lineHeight = parseInt(window.getComputedStyle(textarea).lineHeight);
        const rowHeight = lineHeight * newRows;
        scrollArrow.style.bottom = `calc(11% + ${rowHeight}px)`;
        chatBody.style.height = `calc(100% - ${rowHeight}px - 77px)`;
    }

    resetChatBodyHeight() {
        const chatBody: HTMLElement = this.chatBody.nativeElement;
        const textarea: HTMLTextAreaElement = this.messageTextarea.nativeElement;
        const scrollArrow: HTMLElement = this.scrollArrow.nativeElement;
        textarea.rows = 1;
        scrollArrow.style.bottom = '60 px';
        chatBody.style.height = `calc(100% - 100px)`;
        this.stateStore.dispatch(new NumNewMessagesResetAction());
    }

    private newUserMessage(message: string): IrisClientMessage {
        const content: IrisMessageContent = {
            type: IrisMessageContentType.TEXT,
            textContent: message,
        };
        return {
            sender: this.SENDER_USER,
            content: [content],
        };
    }
}
