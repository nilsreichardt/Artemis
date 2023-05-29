import dayjs from 'dayjs';
import { User } from 'app/core/user/user.model';
import { ProgrammingExercise } from 'app/entities/programming-exercise.model';

export class IrisSession {
    id: number;
    exercise?: ProgrammingExercise;
    user?: User;
    messages: IrisMessage[];
}

export enum IrisSender {
    SERVER = 'LLM',
    USER = 'USER',
    SYSTEM = 'ARTEMIS',
}

export class IrisServerMessage {
    id: number;
    sender: IrisSender.SERVER | IrisSender.SYSTEM;
    content: IrisMessageContent[];
    sentAt: dayjs.Dayjs;
    helpful?: boolean;
}

export class IrisClientMessage {
    id?: number;
    sender: IrisSender.USER;
    content: IrisMessageContent[];
    sentAt?: dayjs.Dayjs;
}

export type IrisMessage = IrisClientMessage | IrisServerMessage;

export enum IrisMessageContentType {
    TEXT = 'text',
}

export class IrisMessageContent {
    type: IrisMessageContentType.TEXT;
    textContent: string;
}

export function isServerSentMessage(message: IrisMessage): message is IrisServerMessage {
    return message.sender === IrisSender.SYSTEM || message.sender === IrisSender.SERVER;
}

export function isStudentSentMessage(message: IrisMessage): message is IrisServerMessage {
    return message.sender === IrisSender.USER;
}
