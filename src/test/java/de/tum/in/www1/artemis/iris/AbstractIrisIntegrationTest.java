package de.tum.in.www1.artemis.iris;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.mockito.ArgumentMatcher;
import org.mockito.ArgumentMatchers;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;

import de.tum.in.www1.artemis.AbstractSpringIntegrationBambooBitbucketJiraTest;
import de.tum.in.www1.artemis.connector.IrisRequestMockProvider;
import de.tum.in.www1.artemis.domain.Course;
import de.tum.in.www1.artemis.domain.ProgrammingExercise;
import de.tum.in.www1.artemis.domain.iris.IrisTemplate;
import de.tum.in.www1.artemis.domain.iris.session.IrisChatSession;
import de.tum.in.www1.artemis.domain.iris.session.IrisCodeEditorSession;
import de.tum.in.www1.artemis.exercise.ExerciseUtilService;
import de.tum.in.www1.artemis.exercise.programmingexercise.ProgrammingExerciseUtilService;
import de.tum.in.www1.artemis.repository.CourseRepository;
import de.tum.in.www1.artemis.repository.ProgrammingExerciseRepository;
import de.tum.in.www1.artemis.repository.iris.IrisSettingsRepository;
import de.tum.in.www1.artemis.repository.iris.IrisTemplateRepository;
import de.tum.in.www1.artemis.service.iris.settings.IrisSettingsService;
import de.tum.in.www1.artemis.user.UserUtilService;

public abstract class AbstractIrisIntegrationTest extends AbstractSpringIntegrationBambooBitbucketJiraTest {

    @Autowired
    protected CourseRepository courseRepository;

    @Autowired
    protected IrisSettingsService irisSettingsService;

    @Autowired
    protected IrisTemplateRepository irisTemplateRepository;

    @Autowired
    @Qualifier("irisRequestMockProvider")
    protected IrisRequestMockProvider irisRequestMockProvider;

    @Autowired
    protected ProgrammingExerciseRepository programmingExerciseRepository;

    @Autowired
    protected UserUtilService userUtilService;

    @Autowired
    protected ExerciseUtilService exerciseUtilService;

    @Autowired
    private IrisSettingsRepository irisSettingsRepository;

    @Autowired
    protected ProgrammingExerciseUtilService programmingExerciseUtilService;

    private static final long TIMEOUT_MS = 200;

    @BeforeEach
    void setup() {
        irisRequestMockProvider.enableMockingOfRequests();
    }

    @AfterEach
    void tearDown() throws Exception {
        irisRequestMockProvider.reset();
    }

    protected void activateIrisGlobally() {
        var globalSettings = irisSettingsService.getGlobalSettings();
        globalSettings.getIrisChatSettings().setEnabled(true);
        globalSettings.getIrisChatSettings().setPreferredModel(null);
        globalSettings.getIrisHestiaSettings().setEnabled(true);
        globalSettings.getIrisHestiaSettings().setPreferredModel(null);
        globalSettings.getIrisCodeEditorSettings().setEnabled(true);
        globalSettings.getIrisCodeEditorSettings().setPreferredModel(null);
        irisSettingsRepository.save(globalSettings);
    }

    protected void activateIrisFor(Course course) {
        var courseSettings = irisSettingsService.getDefaultSettingsFor(course);
        courseSettings.getIrisChatSettings().setEnabled(true);
        courseSettings.getIrisChatSettings().setTemplate(createDummyTemplate());
        courseSettings.getIrisChatSettings().setPreferredModel(null);
        courseSettings.getIrisHestiaSettings().setEnabled(true);
        courseSettings.getIrisHestiaSettings().setTemplate(createDummyTemplate());
        courseSettings.getIrisHestiaSettings().setPreferredModel(null);
        courseSettings.getIrisCodeEditorSettings().setEnabled(true);
        courseSettings.getIrisCodeEditorSettings().setChatTemplate(createDummyTemplate());
        courseSettings.getIrisCodeEditorSettings().setProblemStatementGenerationTemplate(createDummyTemplate());
        courseSettings.getIrisCodeEditorSettings().setTemplateRepoGenerationTemplate(createDummyTemplate());
        courseSettings.getIrisCodeEditorSettings().setSolutionRepoGenerationTemplate(createDummyTemplate());
        courseSettings.getIrisCodeEditorSettings().setTestRepoGenerationTemplate(createDummyTemplate());
        courseSettings.getIrisCodeEditorSettings().setPreferredModel(null);
        irisSettingsRepository.save(courseSettings);
    }

    protected void activateIrisFor(ProgrammingExercise exercise) {
        var exerciseSettings = irisSettingsService.getDefaultSettingsFor(exercise);
        exerciseSettings.getIrisChatSettings().setEnabled(true);
        exerciseSettings.getIrisChatSettings().setTemplate(createDummyTemplate());
        exerciseSettings.getIrisChatSettings().setPreferredModel(null);
        irisSettingsRepository.save(exerciseSettings);
    }

    protected IrisTemplate createDummyTemplate() {
        return new IrisTemplate("Hello World");
    }

    /**
     * Verify that the given messages were sent through the websocket for the given code editor session,
     * and that there were exactly `matchers.length` messages sent.
     *
     * @param session  The code editor session
     * @param matchers Argument matchers which describe the messages that should have been sent
     */
    protected void verifyWebsocketActivityWasExactly(IrisCodeEditorSession session, ArgumentMatcher<?>... matchers) {
        var userLogin = session.getUser().getLogin();
        var topicSuffix = "code-editor-sessions/" + session.getId();
        for (ArgumentMatcher<?> callDescriptor : matchers) {
            verifyMessageWasSentOverWebsocket(userLogin, topicSuffix, callDescriptor);
        }
        verifyNumberOfCallsToWebsocket(userLogin, topicSuffix, matchers.length);
    }

    /**
     * Verify that the given messages were sent through the websocket for the given chat session,
     * and that there were exactly `matchers.length` messages sent.
     *
     * @param session  The chat session
     * @param matchers Argument matchers which describe the messages that should have been sent
     */
    protected void verifyWebsocketActivityWasExactly(IrisChatSession session, ArgumentMatcher<?>... matchers) {
        var userLogin = session.getUser().getLogin();
        var topicSuffix = "sessions/" + session.getId();
        for (ArgumentMatcher<?> callDescriptor : matchers) {
            verifyMessageWasSentOverWebsocket(userLogin, topicSuffix, callDescriptor);
        }
        verifyNumberOfCallsToWebsocket(userLogin, topicSuffix, matchers.length);
    }

    /**
     * Verify that the given message was sent through the websocket for the given user and topic.
     *
     * @param userLogin   The user login
     * @param topicSuffix The topic suffix, e.g. "sessions/123"
     * @param matcher     Argument matcher which describes the message that should have been sent
     */
    private void verifyMessageWasSentOverWebsocket(String userLogin, String topicSuffix, ArgumentMatcher<?> matcher) {
        // @formatter:off
        verify(websocketMessagingService, timeout(TIMEOUT_MS).times(1))
                .sendMessageToUser(
                        eq(userLogin),
                        eq("/topic/iris/" + topicSuffix),
                        ArgumentMatchers.argThat(matcher)
                );
        // @formatter:on
    }

    /**
     * Verify that exactly `numberOfCalls` messages were sent through the websocket for the given user and topic.
     */
    private void verifyNumberOfCallsToWebsocket(String userLogin, String topicSuffix, int numberOfCalls) {
        // @formatter:off
        verify(websocketMessagingService, times(numberOfCalls))
                .sendMessageToUser(
                        eq(userLogin),
                        eq("/topic/iris/" + topicSuffix),
                        any()
                );
        // @formatter:on
    }
}
