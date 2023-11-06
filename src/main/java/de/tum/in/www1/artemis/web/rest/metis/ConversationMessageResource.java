package de.tum.in.www1.artemis.web.rest.metis;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.Principal;
import java.util.List;

import javax.validation.Valid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import de.tum.in.www1.artemis.domain.enumeration.DisplayPriority;
import de.tum.in.www1.artemis.domain.metis.Post;
import de.tum.in.www1.artemis.repository.CourseRepository;
import de.tum.in.www1.artemis.repository.UserRepository;
import de.tum.in.www1.artemis.security.Role;
import de.tum.in.www1.artemis.security.annotations.EnforceAtLeastStudent;
import de.tum.in.www1.artemis.security.annotations.EnforceAtLeastTutor;
import de.tum.in.www1.artemis.service.AuthorizationCheckService;
import de.tum.in.www1.artemis.service.metis.ConversationMessagingService;
import de.tum.in.www1.artemis.service.util.TimeLogUtil;
import de.tum.in.www1.artemis.web.rest.dto.PostContextFilter;
import de.tum.in.www1.artemis.web.rest.errors.BadRequestAlertException;
import io.swagger.annotations.ApiParam;
import tech.jhipster.web.util.PaginationUtil;

/**
 * REST controller for managing Message Posts.
 */
@RestController
@RequestMapping("/api")
public class ConversationMessageResource {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private final ConversationMessagingService conversationMessagingService;

    private final UserRepository userRepository;

    private final AuthorizationCheckService authorizationCheckService;

    private final CourseRepository courseRepository;

    public ConversationMessageResource(ConversationMessagingService conversationMessagingService, UserRepository userRepository,
            AuthorizationCheckService authorizationCheckService, CourseRepository courseRepository) {
        this.conversationMessagingService = conversationMessagingService;
        this.userRepository = userRepository;
        this.authorizationCheckService = authorizationCheckService;
        this.courseRepository = courseRepository;
    }

    /**
     * POST /courses/{courseId}/messages : Create a new message post
     *
     * @param courseId id of the course the message post belongs to
     * @param post     message post to create
     * @return ResponseEntity with status 201 (Created) containing the created message post in the response body,
     *         or with status 400 (Bad Request) if the checks on user, course or post validity fail
     */
    @PostMapping("courses/{courseId}/messages")
    @EnforceAtLeastStudent
    public ResponseEntity<Post> createMessage(@PathVariable Long courseId, @Valid @RequestBody Post post) throws URISyntaxException {
        log.debug("POST createMessage invoked for course {} with post {}", courseId, post.getContent());
        long start = System.nanoTime();
        Post createdMessage = conversationMessagingService.createMessage(courseId, post);
        log.info("createMessage took {}", TimeLogUtil.formatDurationFrom(start));
        return ResponseEntity.created(new URI("/api/courses/" + courseId + "/messages/" + createdMessage.getId())).body(createdMessage);
    }

    /**
     * GET /courses/{courseId}/posts : Get all messages for a conversation by its id or in a list of course-wide channels
     *
     * @param pageable          pagination settings to fetch messages in smaller batches
     * @param postContextFilter request param for filtering messages
     * @param principal         contains the login of the user for the purpose of logging
     * @return ResponseEntity with status 200 (OK) and with body all posts for course, that match the specified context
     *         or 400 (Bad Request) if the checks on user, course or post validity fail
     */
    @GetMapping("courses/{courseId}/messages")
    @EnforceAtLeastStudent
    public ResponseEntity<List<Post>> getMessages(@ApiParam Pageable pageable, PostContextFilter postContextFilter, Principal principal) {
        long timeNanoStart = System.nanoTime();
        Page<Post> coursePosts;

        var requestingUser = userRepository.getUser();
        var course = courseRepository.findByIdElseThrow(postContextFilter.getCourseId());
        authorizationCheckService.checkHasAtLeastRoleInCourseElseThrow(Role.STUDENT, course, requestingUser);

        if (postContextFilter.getConversationId() != null) {
            coursePosts = conversationMessagingService.getMessages(pageable, postContextFilter, requestingUser);
        }
        else if (postContextFilter.getCourseWideChannelIds() != null) {
            coursePosts = conversationMessagingService.getCourseWideMessages(pageable, postContextFilter, requestingUser);
        }
        else {
            throw new BadRequestAlertException("Messages must be associated with a conversion", conversationMessagingService.getEntityName(), "conversationMissing");
        }
        // keep the data as small as possible and avoid unnecessary information sent to the client
        // TODO: in the future we should set conversation to null
        coursePosts.getContent().forEach(post -> {
            if (post.getConversation() != null) {
                post.getConversation().hideDetails();
            }
        });
        HttpHeaders headers = PaginationUtil.generatePaginationHttpHeaders(ServletUriComponentsBuilder.fromCurrentRequest(), coursePosts);
        logDuration(coursePosts.getContent(), principal, timeNanoStart);
        return new ResponseEntity<>(coursePosts.getContent(), headers, HttpStatus.OK);
    }

    private void logDuration(List<Post> posts, Principal principal, long timeNanoStart) {
        if (log.isInfoEnabled()) {
            long answerPosts = posts.stream().mapToLong(post -> post.getAnswers().size()).sum();
            long reactions = posts.stream().mapToLong(post -> post.getReactions().size()).sum();
            long answerReactions = posts.stream().flatMap(post -> post.getAnswers().stream()).mapToLong(answerPost -> answerPost.getReactions().size()).sum();
            log.info("/courses/{courseId}/messages finished in {} for {} posts with {} answer posts, {} reactions, and {} answer post reactions for user {}",
                    TimeLogUtil.formatDurationFrom(timeNanoStart), posts.size(), answerPosts, reactions, answerReactions, principal.getName());
        }
    }

    /**
     * PUT /courses/{courseId}/messages/{messageId} : Update an existing message post with given id
     *
     * @param courseId    id of the course the message post belongs to
     * @param messageId   id of the message post to update
     * @param messagePost message post to update
     * @return ResponseEntity with status 200 (OK) containing the updated message post in the response body,
     *         or with status 400 (Bad Request) if the checks on user, course or post validity fail
     */
    @PutMapping("courses/{courseId}/messages/{messageId}")
    @EnforceAtLeastStudent
    public ResponseEntity<Post> updateMessage(@PathVariable Long courseId, @PathVariable Long messageId, @RequestBody Post messagePost) {
        log.debug("PUT updateMessage invoked for course {} with post {}", courseId, messagePost.getContent());
        long start = System.nanoTime();
        Post updatedMessagePost = conversationMessagingService.updateMessage(courseId, messageId, messagePost);
        log.info("updateMessage took {}", TimeLogUtil.formatDurationFrom(start));
        return new ResponseEntity<>(updatedMessagePost, null, HttpStatus.OK);
    }

    /**
     * DELETE /courses/{courseId}/messages/{id} : Delete a message post by its id
     *
     * @param courseId  id of the course the message post belongs to
     * @param messageId id of the message post to delete
     * @return ResponseEntity with status 200 (OK),
     *         or 400 (Bad Request) if the checks on user, course or post validity fail
     */
    @DeleteMapping("courses/{courseId}/messages/{messageId}")
    @EnforceAtLeastStudent
    public ResponseEntity<Void> deleteMessage(@PathVariable Long courseId, @PathVariable Long messageId) {
        log.debug("DELETE deleteMessage invoked for course {} on message {}", courseId, messageId);
        long start = System.nanoTime();
        conversationMessagingService.deleteMessageById(courseId, messageId);
        // deletion of message posts should not trigger entity deletion alert
        log.info("deleteMessage took {}", TimeLogUtil.formatDurationFrom(start));
        return ResponseEntity.ok().build();
    }

    /**
     * PUT /courses/{courseId}/posts/{postId}/display-priority : Update the display priority of an existing post
     *
     * @param courseId        id of the course the post belongs to
     * @param postId          id of the post change the displayPriority for
     * @param displayPriority new enum value for displayPriority, i.e. either PINNED, ARCHIVED, NONE
     * @return ResponseEntity with status 200 (OK) containing the updated post in the response body,
     *         or with status 400 (Bad Request) if the checks on user, course or post validity fail
     */
    @PutMapping("courses/{courseId}/messages/{postId}/display-priority")
    @EnforceAtLeastTutor
    public ResponseEntity<Post> updateDisplayPriority(@PathVariable Long courseId, @PathVariable Long postId, @RequestParam DisplayPriority displayPriority) {
        Post postWithUpdatedDisplayPriority = conversationMessagingService.changeDisplayPriority(courseId, postId, displayPriority);
        return ResponseEntity.ok().body(postWithUpdatedDisplayPriority);
    }
}
