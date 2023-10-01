package de.tum.in.www1.artemis.web.websocket.jms;

import javax.jms.JMSException;

import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.SpyBean;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import de.tum.in.www1.artemis.AbstractSpringIntegrationIndependentTest;
import de.tum.in.www1.artemis.exception.QuizSubmissionException;
import de.tum.in.www1.artemis.exercise.quizexercise.QuizExerciseUtilService;
import de.tum.in.www1.artemis.repository.QuizExerciseRepository;
import de.tum.in.www1.artemis.service.QuizSubmissionService;

class QuizJMSListenerServiceTest extends AbstractSpringIntegrationIndependentTest {

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    QuizExerciseUtilService quizExerciseUtilService;

    @Autowired
    QuizExerciseRepository quizExerciseRepository;

    @SpyBean
    @Autowired
    QuizSubmissionService quizSubmissionService;

    // Not autowired to reduce number of server starts during tests, created in @BeforeEach
    // QuizJMSListenerService quizJMSListenerService;

    // static EmbeddedActiveMQBroker broker = new EmbeddedActiveMQBroker();

    @BeforeAll
    static void startBroker() {
        // broker.start();
    }

    @AfterAll
    static void stopBroker() {
        // broker.stop();
    }

    @BeforeEach
    void setup() {
        // Autowiring the QuizJMSListenerService would require an additional server start during the test
        // (because of different profiles that are used), therefor we create it manually
        // quizJMSListenerService = new QuizJMSListenerService(objectMapper, quizSubmissionService);
    }

    @Test
    void testCallsQuizSubmission() throws JsonProcessingException, QuizSubmissionException, JMSException {
        /*
         * QuizExercise quizExercise = quizExerciseUtilService.createQuiz(ZonedDateTime.now().minusMinutes(1), null, QuizMode.SYNCHRONIZED);
         * quizExercise.duration(240);
         * quizExerciseRepository.save(quizExercise);
         * var connectionFactory = broker.createConnectionFactory();
         * SimpleMessageListenerContainer simpleMessageListenerContainer = quizJMSListenerService.quizSubmissionMessageListener(connectionFactory,
         * "/queue/quizExercise/" + quizExercise.getId() + "/submission");
         * simpleMessageListenerContainer.afterPropertiesSet();
         * simpleMessageListenerContainer.start();
         * QuizSubmission quizSubmission = QuizExerciseFactory.generateSubmissionForThreeQuestions(quizExercise, 1, false, null);
         * var message = broker.createBytesMessage();
         * message.writeBytes(objectMapper.writeValueAsBytes(quizSubmission));
         * message.setStringProperty("user-name", "user-name1");
         * broker.pushMessage("/queue/quizExercise/" + quizExercise.getId() + "/submission", message);
         * verify(quizSubmissionService, timeout(1000)).saveSubmissionForLiveMode(eq(quizExercise.getId()), any(QuizSubmission.class), eq("user-name1"), eq(false));
         */
    }

    @Test
    void testExtractQuizExerciseIdFromAddress() throws JMSException {
        /*
         * assertThat(QuizJMSListenerService.extractExerciseIdFromAddress("/queue/quizExercise/123/submission")).isEqualTo(123);
         * assertThat(QuizJMSListenerService.extractExerciseIdFromAddress("queue:///queue/quizExercise/123/submission")).isEqualTo(123);
         * assertThatExceptionOfType(JMSException.class).isThrownBy(() -> QuizJMSListenerService.extractExerciseIdFromAddress("/queue/quizExercise/abc/submission"));
         * assertThatExceptionOfType(JMSException.class).isThrownBy(() -> QuizJMSListenerService.extractExerciseIdFromAddress("/queue/some/other/address"));
         */
    }

}
