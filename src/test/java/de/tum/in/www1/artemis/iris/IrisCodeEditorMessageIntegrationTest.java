package de.tum.in.www1.artemis.iris;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.test.context.support.WithMockUser;

import de.tum.in.www1.artemis.domain.Course;
import de.tum.in.www1.artemis.domain.ProgrammingExercise;
import de.tum.in.www1.artemis.domain.iris.message.*;
import de.tum.in.www1.artemis.domain.iris.session.IrisSession;
import de.tum.in.www1.artemis.participation.ParticipationUtilService;
import de.tum.in.www1.artemis.repository.iris.IrisMessageRepository;
import de.tum.in.www1.artemis.repository.iris.IrisSessionRepository;
import de.tum.in.www1.artemis.service.iris.IrisMessageService;
import de.tum.in.www1.artemis.service.iris.IrisSessionService;
import de.tum.in.www1.artemis.util.IrisUtilTestService;
import de.tum.in.www1.artemis.util.LocalRepository;

class IrisCodeEditorMessageIntegrationTest extends AbstractIrisIntegrationTest {

    private static final String TEST_PREFIX = "iriscodeeditormessageintegration";

    @Autowired
    private IrisSessionService irisSessionService;

    @Autowired
    private IrisMessageService irisMessageService;

    @Autowired
    private IrisSessionRepository irisSessionRepository;

    @Autowired
    private IrisMessageRepository irisMessageRepository;

    @Autowired
    private IrisUtilTestService irisUtilTestService;

    @Autowired
    private ParticipationUtilService participationUtilService;

    private ProgrammingExercise exercise;

    private LocalRepository repository;

    @BeforeEach
    void initTestCase() {
        userUtilService.addUsers(TEST_PREFIX, 0, 0, 2, 0);

        final Course course = programmingExerciseUtilService.addCourseWithOneProgrammingExerciseAndTestCases();
        exercise = exerciseUtilService.getFirstExerciseWithType(course, ProgrammingExercise.class);
        // activateIrisFor(course);
        // activateIrisFor(exercise);
        repository = new LocalRepository("main");
    }

    @Test
    @WithMockUser(username = TEST_PREFIX + "editor1", roles = "EDITOR")
    void sendOneMessage() throws Exception {
        var irisSession = irisSessionService.createCodeEditorSession(exercise, userUtilService.getUserByLogin(TEST_PREFIX + "editor1"));
        var messageToSend = createDefaultMockMessage(irisSession);
        messageToSend.setMessageDifferentiator(1453);

        irisRequestMockProvider.mockMessageResponse("Hello World");
        var savedExercise = irisUtilTestService.setupTemplate(exercise, repository);
        // var exerciseParticipation = participationUtilService.addStudentParticipationForProgrammingExercise(savedExercise, TEST_PREFIX + "student1");
        // irisUtilTestService.setupStudentParticipation(exerciseParticipation, repository);
        // activateIrisFor(savedExercise);

        var irisMessage = request.postWithResponseBody("/api/iris/code-editor-sessions/" + irisSession.getId() + "/messages", messageToSend, IrisMessage.class, HttpStatus.CREATED);
        assertThat(irisMessage.getSender()).isEqualTo(IrisMessageSender.USER);
        // assertThat(irisMessage.getHelpful()).isNull();
        assertThat(irisMessage.getMessageDifferentiator()).isEqualTo(1453);
        // Compare contents of messages by only comparing the textContent field
        assertThat(irisMessage.getContent()).hasSize(2).map(IrisMessageContent::getContentAsString)
                .isEqualTo(messageToSend.getContent().stream().map(IrisMessageContent::getContentAsString).toList());
        await().untilAsserted(() -> assertThat(irisSessionRepository.findByIdWithMessagesElseThrow(irisSession.getId()).getMessages()).hasSize(2).contains(irisMessage));

        verifyMessageWasSentOverWebsocket(TEST_PREFIX + "editor1", irisSession.getId(), messageToSend);
        verifyMessageWasSentOverWebsocket(TEST_PREFIX + "editor1", irisSession.getId(), "Hello World");
        verifyNothingElseWasSentOverWebsocket(TEST_PREFIX + "editor1", irisSession.getId());
    }

    @Test
    @WithMockUser(username = TEST_PREFIX + "editor1", roles = "EDITOR")
    void sendOneMessageToWrongSession() throws Exception {
        // var irisSession1 = irisSessionService.createCodeEditorSession(exercise, userUtilService.getUserByLogin(TEST_PREFIX + "editor1"));
        var irisSession2 = irisSessionService.createCodeEditorSession(exercise, userUtilService.getUserByLogin(TEST_PREFIX + "editor2"));
        IrisMessage messageToSend = createDefaultMockMessage(irisSession2);
        request.postWithResponseBody("/api/iris/code-editor-sessions/" + irisSession2.getId() + "/messages", messageToSend, IrisMessage.class, HttpStatus.FORBIDDEN);
    }

    @Test
    @WithMockUser(username = TEST_PREFIX + "editor1", roles = "EDITOR")
    void sendMessageWithoutContent() throws Exception {
        var irisSession = irisSessionService.createCodeEditorSession(exercise, userUtilService.getUserByLogin(TEST_PREFIX + "editor1"));
        var messageToSend = new IrisMessage();
        messageToSend.setSession(irisSession);
        request.postWithResponseBody("/api/iris/code-editor-sessions/" + irisSession.getId() + "/messages", messageToSend, IrisMessage.class, HttpStatus.BAD_REQUEST);
    }

    @Test
    @WithMockUser(username = TEST_PREFIX + "editor1", roles = "EDITOR")
    void sendTwoMessages() throws Exception {
        var irisSession = irisSessionService.createCodeEditorSession(exercise, userUtilService.getUserByLogin(TEST_PREFIX + "editor1"));
        IrisMessage messageToSend1 = createDefaultMockMessage(irisSession);

        var savedExercise = irisUtilTestService.setupTemplate(exercise, repository);
        // var exerciseParticipation = participationUtilService.addStudentParticipationForProgrammingExercise(savedExercise, TEST_PREFIX + "student1");
        // irisUtilTestService.setupStudentParticipation(exerciseParticipation, repository);
        // activateIrisFor(savedExercise);

        var irisMessage1 = request.postWithResponseBody("/api/iris/code-editor-sessions/" + irisSession.getId() + "/messages", messageToSend1, IrisMessage.class,
                HttpStatus.CREATED);
        assertThat(irisMessage1.getSender()).isEqualTo(IrisMessageSender.USER);
        // assertThat(irisMessage1.getHelpful()).isNull();
        // Compare contents of messages by only comparing the textContent field
        assertThat(irisMessage1.getContent()).hasSize(2).map(IrisMessageContent::getContentAsString)
                .isEqualTo(messageToSend1.getContent().stream().map(IrisMessageContent::getContentAsString).toList());
        var irisSessionFromDb = irisSessionRepository.findByIdWithMessagesElseThrow(irisSession.getId());
        assertThat(irisSessionFromDb.getMessages()).hasSize(1).isEqualTo(List.of(irisMessage1));

        IrisMessage messageToSend2 = createDefaultMockMessage(irisSession);
        var irisMessage2 = request.postWithResponseBody("/api/iris/code-editor-sessions/" + irisSession.getId() + "/messages", messageToSend2, IrisMessage.class,
                HttpStatus.CREATED);
        assertThat(irisMessage2.getSender()).isEqualTo(IrisMessageSender.USER);
        // assertThat(irisMessage2.getHelpful()).isNull();
        // Compare contents of messages by only comparing the textContent field
        assertThat(irisMessage2.getContent()).hasSize(2).map(IrisMessageContent::getContentAsString)
                .isEqualTo(messageToSend2.getContent().stream().map(IrisMessageContent::getContentAsString).toList());
        irisSessionFromDb = irisSessionRepository.findByIdWithMessagesElseThrow(irisSession.getId());
        assertThat(irisSessionFromDb.getMessages()).hasSize(2).isEqualTo(List.of(irisMessage1, irisMessage2));
    }

    @Test
    @WithMockUser(username = TEST_PREFIX + "editor1", roles = "EDITOR")
    void getMessages() throws Exception {
        var irisSession = irisSessionService.createCodeEditorSession(exercise, userUtilService.getUserByLogin(TEST_PREFIX + "editor1"));
        IrisMessage message1 = createDefaultMockMessage(irisSession);
        IrisMessage message2 = createDefaultMockMessage(irisSession);
        IrisMessage message3 = createDefaultMockMessage(irisSession);
        IrisMessage message4 = createDefaultMockMessage(irisSession);

        irisMessageService.saveMessage(message1, irisSession, IrisMessageSender.ARTEMIS);
        message2 = irisMessageService.saveMessage(message2, irisSession, IrisMessageSender.LLM);
        message3 = irisMessageService.saveMessage(message3, irisSession, IrisMessageSender.USER);
        message4 = irisMessageService.saveMessage(message4, irisSession, IrisMessageSender.LLM);

        var messages = request.getList("/api/iris/code-editor-sessions/" + irisSession.getId() + "/messages", HttpStatus.OK, IrisMessage.class);
        assertThat(messages)
                .hasSize(3).usingElementComparator((o1, o2) -> o1.getContent().size() == o2.getContent().size() && o1.getContent().stream()
                        .map(IrisMessageContent::getContentAsString).toList().equals(o2.getContent().stream().map(IrisMessageContent::getContentAsString).toList()) ? 0 : -1)
                .isEqualTo(List.of(message2, message3, message4));
    }

    // @Test
    // @WithMockUser(username = TEST_PREFIX + "editor1", roles = "EDITOR")
    // void confirmPlanMessagewithoutChange() throws Exception {
    // var irisSession = irisSessionService.createCodeEditorSession(exercise, userUtilService.getUserByLogin(TEST_PREFIX + "editor1"));
    // var message = new IrisMessage();
    // message.setSession(irisSession);
    // message.addContent(createMockTextContent(message));
    // var irisMessage = irisMessageService.saveMessage(message, irisSession, IrisMessageSender.LLM);
    // request.putWithResponseBody("/api/iris/sessions/" + irisSession.getId() + "/messages/" + irisMessage.getId() + "/helpful/true", null, IrisMessage.class, HttpStatus.OK);
    // irisMessage = irisMessageRepository.findById(irisMessage.getId()).orElseThrow();
    // assertThat(irisMessage.getHelpful()).isTrue();
    // }
    //
    // @Test
    // @WithMockUser(username = TEST_PREFIX + "student1", roles = "USER")
    // void rateMessageHelpfulFalse() throws Exception {
    // var irisSession = irisSessionService.createChatSessionForProgrammingExercise(exercise, userUtilService.getUserByLogin(TEST_PREFIX + "student1"));
    // var message = new IrisMessage();
    // message.setSession(irisSession);
    // message.addContent(createMockTextContent(message));
    // var irisMessage = irisMessageService.saveMessage(message, irisSession, IrisMessageSender.LLM);
    // request.putWithResponseBody("/api/iris/sessions/" + irisSession.getId() + "/messages/" + irisMessage.getId() + "/helpful/false", null, IrisMessage.class, HttpStatus.OK);
    // irisMessage = irisMessageRepository.findById(irisMessage.getId()).orElseThrow();
    // assertThat(irisMessage.getHelpful()).isFalse();
    // }
    //
    // @Test
    // @WithMockUser(username = TEST_PREFIX + "student1", roles = "USER")
    // void rateMessageHelpfulNull() throws Exception {
    // var irisSession = irisSessionService.createChatSessionForProgrammingExercise(exercise, userUtilService.getUserByLogin(TEST_PREFIX + "student1"));
    // var message = new IrisMessage();
    // message.setSession(irisSession);
    // message.addContent(createMockTextContent(message));
    // var irisMessage = irisMessageService.saveMessage(message, irisSession, IrisMessageSender.LLM);
    // request.putWithResponseBody("/api/iris/sessions/" + irisSession.getId() + "/messages/" + irisMessage.getId() + "/helpful/null", null, IrisMessage.class, HttpStatus.OK);
    // irisMessage = irisMessageRepository.findById(irisMessage.getId()).orElseThrow();
    // assertThat(irisMessage.getHelpful()).isNull();
    // }
    //
    // @Test
    // @WithMockUser(username = TEST_PREFIX + "student1", roles = "USER")
    // void rateMessageWrongSender() throws Exception {
    // var irisSession = irisSessionService.createChatSessionForProgrammingExercise(exercise, userUtilService.getUserByLogin(TEST_PREFIX + "student1"));
    // var message = new IrisMessage();
    // message.setSession(irisSession);
    // message.addContent(createMockTextContent(message));
    // var irisMessage = irisMessageService.saveMessage(message, irisSession, IrisMessageSender.USER);
    // request.putWithResponseBody("/api/iris/sessions/" + irisSession.getId() + "/messages/" + irisMessage.getId() + "/helpful/true", null, IrisMessage.class,
    // HttpStatus.BAD_REQUEST);
    // }
    //
    // @Test
    // @WithMockUser(username = TEST_PREFIX + "student1", roles = "USER")
    // void rateMessageWrongSession() throws Exception {
    // var irisSession1 = irisSessionService.createChatSessionForProgrammingExercise(exercise, userUtilService.getUserByLogin(TEST_PREFIX + "student1"));
    // var irisSession2 = irisSessionService.createChatSessionForProgrammingExercise(exercise, userUtilService.getUserByLogin(TEST_PREFIX + "student2"));
    // var message = new IrisMessage();
    // message.setSession(irisSession1);
    // message.addContent(createMockTextContent(message));
    // var irisMessage = irisMessageService.saveMessage(message, irisSession1, IrisMessageSender.USER);
    // request.putWithResponseBody("/api/iris/sessions/" + irisSession2.getId() + "/messages/" + irisMessage.getId() + "/helpful/true", null, IrisMessage.class,
    // HttpStatus.CONFLICT);
    // }
    //
    // @Test
    // @WithMockUser(username = TEST_PREFIX + "student1", roles = "USER")
    // void sendOneMessageBadRequest() throws Exception {
    // var irisSession = irisSessionService.createChatSessionForProgrammingExercise(exercise, userUtilService.getUserByLogin(TEST_PREFIX + "student1"));
    // IrisMessage messageToSend = createDefaultMockMessage(irisSession);
    //
    // irisRequestMockProvider.mockMessageError();
    // var savedExercise = irisUtilTestService.setupTemplate(exercise, repository);
    // var exerciseParticipation = participationUtilService.addStudentParticipationForProgrammingExercise(savedExercise, TEST_PREFIX + "student1");
    // irisUtilTestService.setupStudentParticipation(exerciseParticipation, repository);
    // activateIrisFor(savedExercise);
    //
    // request.postWithResponseBody("/api/iris/sessions/" + irisSession.getId() + "/messages", messageToSend, IrisMessage.class, HttpStatus.CREATED);
    //
    // verifyMessageWasSentOverWebsocket(TEST_PREFIX + "student1", irisSession.getId(), messageToSend);
    // verifyErrorWasSentOverWebsocket(TEST_PREFIX + "student1", irisSession.getId());
    // verifyNothingElseWasSentOverWebsocket(TEST_PREFIX + "student1", irisSession.getId());
    // }
    //
    // @Test
    // @WithMockUser(username = TEST_PREFIX + "student1", roles = "USER")
    // void sendOneMessageEmptyBody() throws Exception {
    // var irisSession = irisSessionService.createChatSessionForProgrammingExercise(exercise, userUtilService.getUserByLogin(TEST_PREFIX + "student1"));
    // IrisMessage messageToSend = createDefaultMockMessage(irisSession);
    //
    // irisRequestMockProvider.mockMessageResponse(null);
    // var savedExercise = irisUtilTestService.setupTemplate(exercise, repository);
    // var exerciseParticipation = participationUtilService.addStudentParticipationForProgrammingExercise(savedExercise, TEST_PREFIX + "student1");
    // irisUtilTestService.setupStudentParticipation(exerciseParticipation, repository);
    // activateIrisFor(savedExercise);
    //
    // request.postWithResponseBody("/api/iris/sessions/" + irisSession.getId() + "/messages", messageToSend, IrisMessage.class, HttpStatus.CREATED);
    //
    // verifyMessageWasSentOverWebsocket(TEST_PREFIX + "student1", irisSession.getId(), messageToSend);
    // verifyErrorWasSentOverWebsocket(TEST_PREFIX + "student1", irisSession.getId());
    // verifyNothingElseWasSentOverWebsocket(TEST_PREFIX + "student1", irisSession.getId());
    // }

    private IrisMessage createDefaultMockMessage(IrisSession irisSession) {
        var messageToSend = new IrisMessage();
        messageToSend.setSession(irisSession);
        messageToSend.addContent(createMockTextContent(messageToSend));
        messageToSend.addContent(createMockExercisePlanContent(messageToSend));
        // messageToSend.addContent(createMockTextContent(messageToSend));
        return messageToSend;
    }

    private IrisMessageContent createMockTextContent(IrisMessage message) {
        String[] adjectives = { "happy", "sad", "angry", "funny", "silly", "crazy", "beautiful", "smart" };
        String[] nouns = { "dog", "cat", "house", "car", "book", "computer", "phone", "shoe" };

        var rdm = ThreadLocalRandom.current();
        String randomAdjective = adjectives[rdm.nextInt(adjectives.length)];
        String randomNoun = nouns[rdm.nextInt(nouns.length)];

        var text = "The " + randomAdjective + " " + randomNoun + " jumped over the lazy dog.";
        var content = new IrisTextMessageContent(message, text);
        content.setId(rdm.nextLong());
        return content;
    }

    private IrisMessageContent createMockExercisePlanContent(IrisMessage message) {
        var content = new IrisExercisePlanMessageContent();
        content.setProblemStatementPlan("I will add more tasks to the problem statement");
        content.setSolutionRepositoryPlan("I will adapt the solution repository");
        content.setTemplateRepositoryPlan("I will document the template repository");
        content.setTestRepositoryPlan("I will add more tests to the test repository");
        content.setId(ThreadLocalRandom.current().nextLong());
        content.setMessage(message);
        return content;
    }
}
