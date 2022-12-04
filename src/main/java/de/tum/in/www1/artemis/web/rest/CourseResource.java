package de.tum.in.www1.artemis.web.rest;

import static java.time.ZonedDateTime.now;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.nio.file.Path;
import java.time.ZonedDateTime;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import javax.validation.constraints.NotNull;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.InputStreamResource;
import org.springframework.core.io.Resource;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import de.tum.in.www1.artemis.config.Constants;
import de.tum.in.www1.artemis.domain.*;
import de.tum.in.www1.artemis.domain.participation.TutorParticipation;
import de.tum.in.www1.artemis.exception.ArtemisAuthenticationException;
import de.tum.in.www1.artemis.repository.*;
import de.tum.in.www1.artemis.security.OAuth2JWKSService;
import de.tum.in.www1.artemis.security.Role;
import de.tum.in.www1.artemis.service.*;
import de.tum.in.www1.artemis.service.connectors.CIUserManagementService;
import de.tum.in.www1.artemis.service.connectors.VcsUserManagementService;
import de.tum.in.www1.artemis.service.dto.StudentDTO;
import de.tum.in.www1.artemis.service.dto.UserDTO;
import de.tum.in.www1.artemis.service.feature.Feature;
import de.tum.in.www1.artemis.service.feature.FeatureToggle;
import de.tum.in.www1.artemis.service.tutorialgroups.TutorialGroupsConfigurationService;
import de.tum.in.www1.artemis.web.rest.dto.*;
import de.tum.in.www1.artemis.web.rest.errors.AccessForbiddenException;
import de.tum.in.www1.artemis.web.rest.errors.BadRequestAlertException;
import de.tum.in.www1.artemis.web.rest.errors.EntityNotFoundException;
import de.tum.in.www1.artemis.web.rest.util.HeaderUtil;
import tech.jhipster.web.util.PaginationUtil;

/**
 * REST controller for managing Course.
 */
@RestController
@RequestMapping("api/")
public class CourseResource {

    private final Logger log = LoggerFactory.getLogger(CourseResource.class);

    @Value("${jhipster.clientApp.name}")
    private String applicationName;

    @Value("${artemis.user-management.course-registration.allowed-username-pattern:#{null}}")
    private Optional<Pattern> allowedCourseRegistrationUsernamePattern;

    @Value("${artemis.course-archives-path}")
    private String courseArchivesDirPath;

    private final UserRepository userRepository;

    private final CourseService courseService;

    private final AuthorizationCheckService authCheckService;

    private final OnlineCourseConfigurationService onlineCourseConfigurationService;

    private final OAuth2JWKSService oAuth2JWKSService;

    private final CourseRepository courseRepository;

    private final ExerciseService exerciseService;

    private final TutorParticipationRepository tutorParticipationRepository;

    private final SubmissionService submissionService;

    private final AssessmentDashboardService assessmentDashboardService;

    private final Optional<VcsUserManagementService> optionalVcsUserManagementService;

    private final Optional<CIUserManagementService> optionalCiUserManagementService;

    private final ExerciseRepository exerciseRepository;

    private final FileService fileService;

    private final TutorialGroupsConfigurationService tutorialGroupsConfigurationService;

    private final CourseScoreCalculationService courseScoreCalculationService;

    public CourseResource(UserRepository userRepository, CourseService courseService, CourseRepository courseRepository, ExerciseService exerciseService,
                          OAuth2JWKSService oAuth2JWKSService, OnlineCourseConfigurationService onlineCourseConfigurationService, AuthorizationCheckService authCheckService,
                          TutorParticipationRepository tutorParticipationRepository, SubmissionService submissionService, Optional<VcsUserManagementService> optionalVcsUserManagementService,
                          AssessmentDashboardService assessmentDashboardService, ExerciseRepository exerciseRepository, Optional<CIUserManagementService> optionalCiUserManagementService,
                          FileService fileService, TutorialGroupsConfigurationService tutorialGroupsConfigurationService, CourseScoreCalculationService courseScoreCalculationService) {
        this.courseService = courseService;
        this.courseRepository = courseRepository;
        this.exerciseService = exerciseService;
        this.oAuth2JWKSService = oAuth2JWKSService;
        this.onlineCourseConfigurationService = onlineCourseConfigurationService;
        this.authCheckService = authCheckService;
        this.tutorParticipationRepository = tutorParticipationRepository;
        this.submissionService = submissionService;
        this.optionalVcsUserManagementService = optionalVcsUserManagementService;
        this.optionalCiUserManagementService = optionalCiUserManagementService;
        this.assessmentDashboardService = assessmentDashboardService;
        this.userRepository = userRepository;
        this.exerciseRepository = exerciseRepository;
        this.fileService = fileService;
        this.tutorialGroupsConfigurationService = tutorialGroupsConfigurationService;
        this.courseScoreCalculationService = courseScoreCalculationService;
    }

    /**
     * PUT /courses/:courseId : Updates an existing updatedCourse.
     *
     * @param courseId     the id of the course to update
     * @param courseUpdate the course to update
     * @param file         the optional course icon file
     * @return the ResponseEntity with status 200 (OK) and with body the updated course
     */
    @PutMapping(value = "courses/{courseId}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @PreAuthorize("hasRole('INSTRUCTOR')")
    public ResponseEntity<Course> updateCourse(@PathVariable Long courseId, @RequestPart("course") Course courseUpdate, @RequestPart(required = false) MultipartFile file) {
        log.debug("REST request to update Course : {}", courseUpdate);
        User user = userRepository.getUserWithGroupsAndAuthorities();

        var existingCourse = courseRepository.findByIdWithOrganizationsAndLearningGoalsAndOnlineConfigurationElseThrow(courseUpdate.getId());

        if (existingCourse.getTimeZone() != null && courseUpdate.getTimeZone() == null) {
            throw new IllegalArgumentException("You can not remove the time zone of a course");
        }

        var timeZoneChanged = (existingCourse.getTimeZone() != null && courseUpdate.getTimeZone() != null && !existingCourse.getTimeZone().equals(courseUpdate.getTimeZone()));

        if (!Objects.equals(existingCourse.getShortName(), courseUpdate.getShortName())) {
            throw new BadRequestAlertException("The course short name cannot be changed", Course.ENTITY_NAME, "shortNameCannotChange", true);
        }

        // only allow admins or instructors of the existing course to change it
        // this is important, otherwise someone could put himself into the instructor group of the updated course
        authCheckService.checkHasAtLeastRoleInCourseElseThrow(Role.INSTRUCTOR, existingCourse, user);

        Set<String> existingGroupNames = Set.of(existingCourse.getStudentGroupName(), existingCourse.getTeachingAssistantGroupName(), existingCourse.getEditorGroupName(),
            existingCourse.getInstructorGroupName());
        Set<String> newGroupNames = Set.of(courseUpdate.getStudentGroupName(), courseUpdate.getTeachingAssistantGroupName(), courseUpdate.getEditorGroupName(),
            courseUpdate.getInstructorGroupName());
        Set<String> changedGroupNames = new HashSet<>(newGroupNames);
        changedGroupNames.removeAll(existingGroupNames);

        if (authCheckService.isAdmin(user)) {
            // if an admin changes a group, we need to check that the changed group exists
            try {
                changedGroupNames.forEach(courseService::checkIfGroupsExists);
            } catch (ArtemisAuthenticationException ex) {
                // a specified group does not exist, notify the client
                throw new BadRequestAlertException(ex.getMessage(), Course.ENTITY_NAME, "groupNotFound", true);
            }
        } else {
            // this means the user must be an instructor, who has NO Admin rights.
            // instructors are not allowed to change group names, because this would lead to security problems
            if (!changedGroupNames.isEmpty()) {
                throw new BadRequestAlertException("You are not allowed to change the group names of a course", Course.ENTITY_NAME, "groupNamesCannotChange", true);
            }
        }

        // Make sure to preserve associations in updated entity
        courseUpdate.setId(courseId);
        courseUpdate.setPrerequisites(existingCourse.getPrerequisites());
        courseUpdate.setTutorialGroupsConfiguration(existingCourse.getTutorialGroupsConfiguration());
        courseUpdate.setOnlineCourseConfiguration(existingCourse.getOnlineCourseConfiguration());

        courseUpdate.validateRegistrationConfirmationMessage();
        courseUpdate.validateComplaintsAndRequestMoreFeedbackConfig();
        courseUpdate.validateOnlineCourseAndRegistrationEnabled();
        courseUpdate.validateShortName();
        courseUpdate.validateAccuracyOfScores();
        if (!courseUpdate.isValidStartAndEndDate()) {
            throw new BadRequestAlertException("For Courses, the start date has to be before the end date", Course.ENTITY_NAME, "invalidCourseStartDate", true);
        }

        if (file != null) {
            String pathString = fileService.handleSaveFile(file, false, false);
            courseUpdate.setCourseIcon(pathString);
        }

        if (courseUpdate.isOnlineCourse() != existingCourse.isOnlineCourse()) {
            if (courseUpdate.isOnlineCourse()) {
                onlineCourseConfigurationService.createOnlineCourseConfiguration(courseUpdate);
            } else {
                courseUpdate.setOnlineCourseConfiguration(null);
            }
        }

        courseUpdate.setId(courseId); // Don't persist a wrong ID
        Course result = courseRepository.save(courseUpdate);

        // Based on the old instructors, editors and TAs, we can update all exercises in the course in the VCS (if necessary)
        // We need the old instructors, editors and TAs, so that the VCS user management service can determine which
        // users no longer have TA, editor or instructor rights in the related exercise repositories.
        final var oldInstructorGroup = existingCourse.getInstructorGroupName();
        final var oldEditorGroup = existingCourse.getEditorGroupName();
        final var oldTeachingAssistantGroup = existingCourse.getTeachingAssistantGroupName();

        optionalVcsUserManagementService
            .ifPresent(userManagementService -> userManagementService.updateCoursePermissions(result, oldInstructorGroup, oldEditorGroup, oldTeachingAssistantGroup));
        optionalCiUserManagementService
            .ifPresent(ciUserManagementService -> ciUserManagementService.updateCoursePermissions(result, oldInstructorGroup, oldEditorGroup, oldTeachingAssistantGroup));
        if (timeZoneChanged) {
            tutorialGroupsConfigurationService.onTimeZoneUpdate(result);
        }
        return ResponseEntity.ok(result);
    }

    /**
     * PUT courses/:courseId/onlineCourseConfiguration : Updates the onlineCourseConfiguration for the given cours.
     *
     * @param courseId                  the id of the course to update
     * @param onlineCourseConfiguration the online course configuration to update
     * @return the ResponseEntity with status 200 (OK) and with body the updated online course configuration
     */
    @PutMapping("courses/{courseId}/onlineCourseConfiguration")
    @PreAuthorize("hasRole('INSTRUCTOR')")
    public ResponseEntity<OnlineCourseConfiguration> updateOnlineCourseConfiguration(@PathVariable Long courseId,
                                                                                     @RequestBody OnlineCourseConfiguration onlineCourseConfiguration) {
        log.debug("REST request to update the online course configuration for Course : {}", courseId);

        Course course = courseRepository.findByIdWithEagerOnlineCourseConfigurationElseThrow(courseId);
        authCheckService.checkHasAtLeastRoleInCourseElseThrow(Role.INSTRUCTOR, course, null);

        if (!course.isOnlineCourse()) {
            throw new BadRequestAlertException("Course must be online course", Course.ENTITY_NAME, "courseMustBeOnline");
        }

        if (!course.getOnlineCourseConfiguration().getId().equals(onlineCourseConfiguration.getId())) {
            throw new BadRequestAlertException("The onlineCourseConfigurationId does not match the id of the course's onlineCourseConfiguration",
                OnlineCourseConfiguration.ENTITY_NAME, "idMismatch");
        }

        onlineCourseConfigurationService.validateOnlineCourseConfiguration(onlineCourseConfiguration);
        course.setOnlineCourseConfiguration(onlineCourseConfiguration);

        courseRepository.save(course);

        oAuth2JWKSService.updateKey(course.getOnlineCourseConfiguration().getRegistrationId());

        return ResponseEntity.ok(onlineCourseConfiguration);
    }

    /**
     * POST /courses/{courseId}/register : Register for an existing course. This method registers the current user for the given course id in case the course has already started
     * and not finished yet. The user is added to the course student group in the Authentication System and the course student group is added to the user's groups in the Artemis
     * database.
     *
     * @param courseId to find the course
     * @return response entity for user who has been registered to the course
     */
    @PostMapping("courses/{courseId}/register")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<User> registerForCourse(@PathVariable Long courseId) {
        Course course = courseRepository.findWithEagerOrganizationsElseThrow(courseId);
        User user = userRepository.getUserWithGroupsAndAuthoritiesAndOrganizations();
        log.debug("REST request to register {} for Course {}", user.getName(), course.getTitle());
        if (allowedCourseRegistrationUsernamePattern.isPresent() && !allowedCourseRegistrationUsernamePattern.get().matcher(user.getLogin()).matches()) {
            return ResponseEntity.badRequest().headers(HeaderUtil.createFailureAlert(applicationName, false, Course.ENTITY_NAME, "registrationNotAllowed",
                "Registration with this username is not allowed. Cannot register user")).body(null);
        }
        if (course.getStartDate() != null && course.getStartDate().isAfter(now())) {
            return ResponseEntity.badRequest()
                .headers(HeaderUtil.createFailureAlert(applicationName, false, Course.ENTITY_NAME, "courseNotStarted", "The course has not yet started. Cannot register user"))
                .body(null);
        }
        if (course.getEndDate() != null && course.getEndDate().isBefore(now())) {
            return ResponseEntity.badRequest().headers(
                    HeaderUtil.createFailureAlert(applicationName, false, Course.ENTITY_NAME, "courseAlreadyFinished", "The course has already finished. Cannot register user"))
                .body(null);
        }
        if (!Boolean.TRUE.equals(course.isRegistrationEnabled())) {
            return ResponseEntity.badRequest().headers(HeaderUtil.createFailureAlert(applicationName, false, Course.ENTITY_NAME, "registrationDisabled",
                "The course does not allow registration. Cannot register user")).body(null);
        }
        if (course.getOrganizations() != null && !course.getOrganizations().isEmpty() && !courseRepository.checkIfUserIsMemberOfCourseOrganizations(user, course)) {
            return ResponseEntity.badRequest().headers(HeaderUtil.createFailureAlert(applicationName, false, Course.ENTITY_NAME, "registrationNotAllowed",
                "User is not member of any organization of this course. Cannot register user")).body(null);
        }
        courseService.registerUserForCourse(user, course);
        return ResponseEntity.ok(user);
    }

    /**
     * GET /courses : get all courses for administration purposes.
     *
     * @param onlyActive if true, only active courses will be considered in the result
     * @return the list of courses (the user has access to)
     */
    @GetMapping("courses")
    @PreAuthorize("hasRole('TA')")
    public List<Course> getAllCourses(@RequestParam(defaultValue = "false") boolean onlyActive) {
        log.debug("REST request to get all Courses the user has access to");
        User user = userRepository.getUserWithGroupsAndAuthorities();
        List<Course> courses = courseRepository.findAll();
        Stream<Course> userCourses = courses.stream().filter(course -> user.getGroups().contains(course.getTeachingAssistantGroupName())
            || user.getGroups().contains(course.getInstructorGroupName()) || authCheckService.isAdmin(user));
        if (onlyActive) {
            // only include courses that have NOT been finished
            userCourses = userCourses.filter(course -> course.getEndDate() == null || course.getEndDate().isAfter(ZonedDateTime.now()));
        }
        return userCourses.toList();
    }

    /**
     * GET /courses/courses-with-quiz : get all courses with quiz exercises for administration purposes.
     *
     * @return the list of courses
     */
    @GetMapping("courses/courses-with-quiz")
    @PreAuthorize("hasRole('EDITOR')")
    public List<Course> getAllCoursesWithQuizExercises() {
        User user = userRepository.getUserWithGroupsAndAuthorities();
        if (authCheckService.isAdmin(user)) {
            return courseRepository.findAllWithQuizExercisesWithEagerExercises();
        } else {
            var userGroups = new ArrayList<>(user.getGroups());
            return courseRepository.getCoursesWithQuizExercisesForWhichUserHasAtLeastEditorAccess(userGroups);
        }
    }

    /**
     * GET /courses/with-user-stats : get all courses for administration purposes with user stats.
     *
     * @param onlyActive if true, only active courses will be considered in the result
     * @return the list of courses (the user has access to)
     */
    @GetMapping("courses/with-user-stats")
    @PreAuthorize("hasRole('TA')")
    public List<Course> getAllCoursesWithUserStats(@RequestParam(defaultValue = "false") boolean onlyActive) {
        log.debug("get courses with user stats, only active: {}", onlyActive);
        List<Course> courses = getAllCourses(onlyActive);
        for (Course course : courses) {
            course.setNumberOfInstructors(userRepository.countUserInGroup(course.getInstructorGroupName()));
            course.setNumberOfTeachingAssistants(userRepository.countUserInGroup(course.getTeachingAssistantGroupName()));
            course.setNumberOfEditors(userRepository.countUserInGroup(course.getEditorGroupName()));
            course.setNumberOfStudents(userRepository.countUserInGroup(course.getStudentGroupName()));
        }
        return courses;
    }

    /**
     * GET /courses/course-overview : get all courses for the management overview
     *
     * @param onlyActive if true, only active courses will be considered in the result
     * @return a list of courses (the user has access to)
     */
    @GetMapping("courses/course-management-overview")
    @PreAuthorize("hasRole('TA')")
    public List<Course> getAllCoursesForManagementOverview(@RequestParam(defaultValue = "false") boolean onlyActive) {
        return courseService.getAllCoursesForManagementOverview(onlyActive);
    }

    /**
     * GET /courses/for-registration : get all courses that the current user can register to.
     * Decided by the start and end date and if the registrationEnabled flag is set correctly
     *
     * @return the list of courses which are active
     */
    @GetMapping("courses/for-registration")
    @PreAuthorize("hasRole('USER')")
    public List<Course> getAllCoursesToRegister() {
        log.debug("REST request to get all currently active Courses that are not online courses");
        User user = userRepository.getUserWithGroupsAndAuthoritiesAndOrganizations();

        List<Course> allRegisteredCourses = courseService.findAllActiveForUser(user);
        List<Course> allCoursesToRegister = courseRepository.findAllCurrentlyActiveNotOnlineAndRegistrationEnabledWithOrganizationsAndPrerequisites();
        return allCoursesToRegister.stream().filter(course -> {
            // further, check if the course has been assigned to any organization and if yes,
            // check if user is member of at least one of them
            if (course.getOrganizations() != null && !course.getOrganizations().isEmpty()) {
                return courseRepository.checkIfUserIsMemberOfCourseOrganizations(user, course);
            } else {
                return true;
            }
        }).filter(course -> !allRegisteredCourses.contains(course)).toList();
    }

    /**
     * GET /courses/{courseId}/for-dashboard
     *
     * @param courseId the courseId for which exercises, lectures, exams and learning goals should be fetched
     * @return a course with all exercises, lectures, exams and learning goals visible to the student
     */
    @GetMapping("courses/{courseId}/for-dashboard")
    @PreAuthorize("hasRole('USER')")
    public Course getCourseForDashboard(@PathVariable long courseId) {
        long start = System.currentTimeMillis();
        User user = userRepository.getUserWithGroupsAndAuthorities();

        Course course = courseService.findOneWithExercisesAndLecturesAndExamsAndLearningGoalsAndTutorialGroupsForUser(courseId, user);
        courseService.fetchParticipationsWithSubmissionsAndResultsForCourses(List.of(course), user, start);
        return course;
    }

    /**
     * GET /courses/for-dashboard
     *
     * @return the list of courses (the user has access to) including all exercises with participation and result for the user +
     * the calculated scores the user achieved in each of those courses (including reachablePoints, and absolutePoints i.a.)
     */
    @GetMapping("courses/for-dashboard")
    @PreAuthorize("hasRole('USER')")
    public Map<String, Object> getAllCoursesForDashboard() {
        long start = System.currentTimeMillis();
        log.debug("REST request to get all Courses the user has access to with exercises, participations and results + the calculated scores the user achieved in each of those courses");
        User user = userRepository.getUserWithGroupsAndAuthorities();

        // get all courses with exercises for this user
        List<Course> courses = courseService.findAllActiveWithExercisesAndLecturesAndExamsForUser(user);
        courseService.fetchParticipationsWithSubmissionsAndResultsForCourses(courses, user, start);

        Map<Long, Map<String, CourseScoresDTO>> scores = new HashMap<>();
        courses.forEach(course -> {
            scores.put(course.getId(), courseScoreCalculationService.calculateCourseScoresPerExerciseType(course.getId(), user.getId()));
        });
        log.info("get all courses for dashboard took {}ms", System.currentTimeMillis() - start);
        return Map.of("courses", courses, "scores", scores);
    }

    /**
     * GET /courses/for-notifications
     *
     * @return the list of courses (the user has access to)
     */
    @GetMapping("courses/for-notifications")
    @PreAuthorize("hasRole('USER')")
    public List<Course> getAllCoursesForNotifications() {
        log.debug("REST request to get all Courses the user has access to");
        User user = userRepository.getUserWithGroupsAndAuthorities();
        return courseService.findAllActiveForUser(user);
    }

    /**
     * GET /courses/:courseId/for-assessment-dashboard
     *
     * @param courseId the id of the course to retrieve
     * @return data about a course including all exercises, plus some data for the tutor as tutor status for assessment
     */
    @GetMapping("courses/{courseId}/for-assessment-dashboard")
    @PreAuthorize("hasRole('TA')")
    public ResponseEntity<Course> getCourseForAssessmentDashboard(@PathVariable long courseId) {
        log.debug("REST request /courses/{courseId}/for-assessment-dashboard");
        Course course = courseRepository.findWithEagerExercisesById(courseId);
        User user = userRepository.getUserWithGroupsAndAuthorities();
        authCheckService.checkHasAtLeastRoleInCourseElseThrow(Role.TEACHING_ASSISTANT, course, user);

        Set<Exercise> interestingExercises = courseRepository.getInterestingExercisesForAssessmentDashboards(course.getExercises());
        course.setExercises(interestingExercises);
        List<TutorParticipation> tutorParticipations = tutorParticipationRepository.findAllByAssessedExercise_Course_IdAndTutor_Id(course.getId(), user.getId());
        assessmentDashboardService.generateStatisticsForExercisesForAssessmentDashboard(course.getExercises(), tutorParticipations, false);
        return ResponseEntity.ok(course);
    }

    /**
     * GET /courses/:courseId/stats-for-assessment-dashboard A collection of useful statistics for the tutor course dashboard, including: - number of submissions to the course -
     * number of assessments - number of assessments assessed by the tutor - number of complaints
     * <p>
     * all timestamps were measured when calling this method from the PGdP assessment-dashboard
     *
     * @param courseId the id of the course to retrieve
     * @return data about a course including all exercises, plus some data for the tutor as tutor status for assessment
     */
    @GetMapping("courses/{courseId}/stats-for-assessment-dashboard")
    @PreAuthorize("hasRole('TA')")
    public ResponseEntity<StatsForDashboardDTO> getStatsForAssessmentDashboard(@PathVariable long courseId) {
        Course course = courseRepository.findByIdElseThrow(courseId);
        authCheckService.checkHasAtLeastRoleInCourseElseThrow(Role.TEACHING_ASSISTANT, course, null);
        StatsForDashboardDTO stats = courseService.getStatsForDashboardDTO(course);
        return ResponseEntity.ok(stats);
    }

    /**
     * GET /courses/:courseId : get the "id" course.
     *
     * @param courseId the id of the course to retrieve
     * @return the ResponseEntity with status 200 (OK) and with body the course, or with status 404 (Not Found)
     */
    @GetMapping("courses/{courseId}")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<Course> getCourse(@PathVariable Long courseId) {
        log.debug("REST request to get Course : {}", courseId);
        Course course = courseRepository.findByIdElseThrow(courseId);

        User user = userRepository.getUserWithGroupsAndAuthorities();
        authCheckService.checkHasAtLeastRoleInCourseElseThrow(Role.STUDENT, course, user);

        if (authCheckService.isAtLeastInstructorInCourse(course, user)) {
            course = courseRepository.findByIdWithEagerOnlineCourseConfigurationAndTutorialGroupConfigurationElseThrow(courseId);
        } else if (authCheckService.isAtLeastTeachingAssistantInCourse(course, user)) {
            course = courseRepository.findByIdWithEagerTutorialGroupConfigurationElseThrow(courseId);
        }

        if (authCheckService.isAtLeastTeachingAssistantInCourse(course, user)) {
            course.setNumberOfInstructors(userRepository.countUserInGroup(course.getInstructorGroupName()));
            course.setNumberOfTeachingAssistants(userRepository.countUserInGroup(course.getTeachingAssistantGroupName()));
            course.setNumberOfEditors(userRepository.countUserInGroup(course.getEditorGroupName()));
            course.setNumberOfStudents(userRepository.countUserInGroup(course.getStudentGroupName()));
        }

        return ResponseEntity.ok(course);
    }

    /**
     * GET /courses/:courseId : get the "id" course.
     *
     * @param courseId the id of the course to retrieve
     * @return the ResponseEntity with status 200 (OK) and with body the course, or with status 404 (Not Found)
     */
    @GetMapping("courses/{courseId}/with-exercises")
    @PreAuthorize("hasRole('TA')")
    public ResponseEntity<Course> getCourseWithExercises(@PathVariable Long courseId) {
        log.debug("REST request to get Course : {}", courseId);
        Course course = courseRepository.findWithEagerExercisesById(courseId);
        authCheckService.checkHasAtLeastRoleInCourseElseThrow(Role.TEACHING_ASSISTANT, course, null);
        return ResponseEntity.ok(course);
    }

    /**
     * GET /courses/:courseId/with-organizations Get a course by id with eagerly loaded organizations
     *
     * @param courseId the id of the course
     * @return the course with eagerly loaded organizations
     */
    @GetMapping("courses/{courseId}/with-organizations")
    @PreAuthorize("hasRole('TA')")
    public ResponseEntity<Course> getCourseWithOrganizations(@PathVariable Long courseId) {
        log.debug("REST request to get a course with its organizations : {}", courseId);
        Course course = courseRepository.findWithEagerOrganizationsElseThrow(courseId);
        authCheckService.checkHasAtLeastRoleInCourseElseThrow(Role.TEACHING_ASSISTANT, course, null);
        return ResponseEntity.ok(course);
    }

    /**
     * GET /courses/:courseId/lockedSubmissions Get locked submissions for course for user
     *
     * @param courseId the id of the course
     * @return the ResponseEntity with status 200 (OK) and with body the course, or with status 404 (Not Found)
     */
    @GetMapping("courses/{courseId}/lockedSubmissions")
    @PreAuthorize("hasRole('TA')")
    public ResponseEntity<List<Submission>> getLockedSubmissionsForCourse(@PathVariable Long courseId) {
        log.debug("REST request to get all locked submissions for course : {}", courseId);
        Course course = courseRepository.findWithEagerExercisesById(courseId);
        User user = userRepository.getUserWithGroupsAndAuthorities();
        authCheckService.checkHasAtLeastRoleInCourseElseThrow(Role.TEACHING_ASSISTANT, course, user);

        List<Submission> submissions = submissionService.getLockedSubmissions(courseId);
        for (Submission submission : submissions) {
            submissionService.hideDetails(submission, user);
        }

        return ResponseEntity.ok(submissions);
    }

    /**
     * GET /courses/exercises-for-management-overview
     * <p>
     * gets the courses with exercises for the user
     *
     * @param onlyActive if true, only active courses will be considered in the result
     * @return ResponseEntity with status, containing a list of courses
     */
    @GetMapping("courses/exercises-for-management-overview")
    @PreAuthorize("hasRole('TA')")
    public ResponseEntity<List<Course>> getExercisesForCourseOverview(@RequestParam(defaultValue = "false") boolean onlyActive) {
        final List<Course> courses = new ArrayList<>();
        for (final var course : courseService.getAllCoursesForManagementOverview(onlyActive)) {
            course.setExercises(exerciseRepository.getExercisesForCourseManagementOverview(course.getId()));
            courses.add(course);
        }
        return ResponseEntity.ok(courses);
    }

    /**
     * GET /courses/stats-for-management-overview
     * <p>
     * gets the statistics for the courses of the user
     * statistics for exercises with an assessment due date (or due date if there is no assessment due date)
     * in the past are limited to the five most recent
     *
     * @param onlyActive if true, only active courses will be considered in the result
     * @return ResponseEntity with status, containing a list of <code>CourseManagementOverviewStatisticsDTO</code>
     */
    @GetMapping("courses/stats-for-management-overview")
    @PreAuthorize("hasRole('TA')")
    public ResponseEntity<List<CourseManagementOverviewStatisticsDTO>> getExerciseStatsForCourseOverview(@RequestParam(defaultValue = "false") boolean onlyActive) {
        final List<CourseManagementOverviewStatisticsDTO> courseDTOs = new ArrayList<>();
        for (final var course : courseService.getAllCoursesForManagementOverview(onlyActive)) {
            final var courseId = course.getId();
            final var courseDTO = new CourseManagementOverviewStatisticsDTO();
            courseDTO.setCourseId(courseId);

            var studentsGroup = courseRepository.findStudentGroupName(courseId);
            var amountOfStudentsInCourse = Math.toIntExact(userRepository.countUserInGroup(studentsGroup));
            courseDTO.setExerciseDTOS(exerciseService.getStatisticsForCourseManagementOverview(courseId, amountOfStudentsInCourse));

            var exerciseIds = exerciseRepository.findAllIdsByCourseId(courseId);
            var endDate = courseService.determineEndDateForActiveStudents(course);
            var timeSpanSize = courseService.determineTimeSpanSizeForActiveStudents(course, endDate, 4);
            courseDTO.setActiveStudents(courseService.getActiveStudents(exerciseIds, 0, timeSpanSize, endDate));
            courseDTOs.add(courseDTO);
        }

        return ResponseEntity.ok(courseDTOs);
    }

    /**
     * PUT /courses/{courseId} : archive an existing course asynchronously. This method starts the process of archiving all course exercises, submissions and results in a large
     * zip file. It immediately returns and runs this task asynchronously. When the task is done, the course is marked as archived, which means the zip file can be downloaded.
     *
     * @param courseId the id of the course
     * @return empty
     */
    @PutMapping("courses/{courseId}/archive")
    @PreAuthorize("hasRole('INSTRUCTOR')")
    @FeatureToggle(Feature.Exports)
    public ResponseEntity<Void> archiveCourse(@PathVariable Long courseId) {
        log.info("REST request to archive Course : {}", courseId);
        final Course course = courseRepository.findByIdWithExercisesAndLecturesElseThrow(courseId);
        authCheckService.checkHasAtLeastRoleInCourseElseThrow(Role.INSTRUCTOR, course, null);
        // Archiving a course is only possible after the course is over
        if (now().isBefore(course.getEndDate())) {
            throw new BadRequestAlertException("You cannot archive a course that is not over.", Course.ENTITY_NAME, "courseNotOver", true);
        }
        courseService.archiveCourse(course);

        // Note: in the first version, we do not store the results with feedback and other metadata, as those will stay available in Artemis, the main focus is to allow
        // instructors to download student repos in order to delete those on Bitbucket/Gitlab

        // Note: Lectures are not part of the archive at the moment and will be included in a future version
        // 1) Get all lectures (attachments) of the course and store them in a folder

        // Note: Questions and answers are not part of the archive at the moment and will be included in a future version
        // 1) Get all questions and answers for exercises and lectures and store those in structured text files

        return ResponseEntity.ok().build();
    }

    /**
     * Downloads the zip file of the archived course if it exists. Throws a 404 if the course doesn't exist
     *
     * @param courseId The course id of the archived course
     * @return ResponseEntity with status
     */
    @PreAuthorize("hasRole('INSTRUCTOR')")
    @GetMapping("courses/{courseId}/download-archive")
    public ResponseEntity<Resource> downloadCourseArchive(@PathVariable Long courseId) throws FileNotFoundException {
        log.info("REST request to download archive of Course : {}", courseId);
        final Course course = courseRepository.findByIdElseThrow(courseId);
        authCheckService.checkHasAtLeastRoleInCourseElseThrow(Role.INSTRUCTOR, course, null);
        if (!course.hasCourseArchive()) {
            throw new EntityNotFoundException("Archived course", courseId);
        }

        // The path is stored in the course table
        Path archive = Path.of(courseArchivesDirPath, course.getCourseArchivePath());

        File zipFile = archive.toFile();
        InputStreamResource resource = new InputStreamResource(new FileInputStream(zipFile));
        return ResponseEntity.ok().contentLength(zipFile.length()).contentType(MediaType.APPLICATION_OCTET_STREAM).header("filename", zipFile.getName()).body(resource);
    }

    /**
     * DELETE /courses/:course/cleanup : Cleans up a course by deleting all student submissions.
     *
     * @param courseId id of the course to clean up
     * @return ResponseEntity with status
     */
    @DeleteMapping("courses/{courseId}/cleanup")
    @PreAuthorize("hasRole('INSTRUCTOR')")
    public ResponseEntity<Resource> cleanup(@PathVariable Long courseId) {
        log.info("REST request to cleanup the Course : {}", courseId);
        final Course course = courseRepository.findByIdElseThrow(courseId);
        authCheckService.checkHasAtLeastRoleInCourseElseThrow(Role.INSTRUCTOR, course, null);
        // Forbid cleaning the course if no archive has been created
        if (!course.hasCourseArchive()) {
            throw new BadRequestAlertException("Failed to clean up course " + courseId + " because it needs to be archived first.", Course.ENTITY_NAME, "archivenonexistant");
        }
        courseService.cleanupCourse(courseId);
        return ResponseEntity.ok().build();
    }

    /**
     * GET /courses/:courseId/categories : Returns all categories used in a course
     *
     * @param courseId the id of the course to get the categories from
     * @return the ResponseEntity with status 200 (OK) and the list of categories or with status 404 (Not Found)
     */
    @GetMapping("courses/{courseId}/categories")
    @PreAuthorize("hasRole('EDITOR')")
    public ResponseEntity<Set<String>> getCategoriesInCourse(@PathVariable Long courseId) {
        log.debug("REST request to get categories of Course : {}", courseId);
        Course course = courseRepository.findByIdElseThrow(courseId);
        authCheckService.checkHasAtLeastRoleInCourseElseThrow(Role.EDITOR, course, null);
        return ResponseEntity.ok().body(exerciseRepository.findAllCategoryNames(course.getId()));
    }

    /**
     * GET /courses/:courseId/students : Returns all users that belong to the student group of the course
     *
     * @param courseId the id of the course
     * @return list of users with status 200 (OK)
     */
    @GetMapping("courses/{courseId}/students")
    @PreAuthorize("hasRole('INSTRUCTOR')")
    public ResponseEntity<List<User>> getAllStudentsInCourse(@PathVariable Long courseId) {
        log.debug("REST request to get all students in course : {}", courseId);
        Course course = courseRepository.findByIdElseThrow(courseId);
        return courseService.getAllUsersInGroup(course, course.getStudentGroupName());
    }

    /**
     * GET /courses/:courseId/students/search : Search all users by login or name that belong to the student group of the course
     *
     * @param courseId    the id of the course
     * @param loginOrName the login or name by which to search users
     * @return the ResponseEntity with status 200 (OK) and with body all users
     */
    @GetMapping("courses/{courseId}/students/search")
    @PreAuthorize("hasRole('TA')")
    public ResponseEntity<List<UserDTO>> searchStudentsInCourse(@PathVariable Long courseId, @RequestParam("loginOrName") String loginOrName) {
        log.debug("REST request to search for students in course : {} with login or name : {}", courseId, loginOrName);
        Course course = courseRepository.findByIdElseThrow(courseId);
        authCheckService.checkHasAtLeastRoleInCourseElseThrow(Role.TEACHING_ASSISTANT, course, null);
        // restrict result size by only allowing reasonable searches
        if (loginOrName.length() < 3) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Query param 'loginOrName' must be three characters or longer.");
        }
        final Page<UserDTO> page = userRepository.searchAllUsersByLoginOrNameInGroupAndConvertToDTO(PageRequest.of(0, 25), loginOrName, course.getStudentGroupName());
        HttpHeaders headers = PaginationUtil.generatePaginationHttpHeaders(ServletUriComponentsBuilder.fromCurrentRequest(), page);
        return new ResponseEntity<>(page.getContent(), headers, HttpStatus.OK);
    }

    /**
     * GET /courses/:courseId/tutors : Returns all users that belong to the tutor group of the course
     *
     * @param courseId the id of the course
     * @return list of users with status 200 (OK)
     */
    @GetMapping("courses/{courseId}/tutors")
    @PreAuthorize("hasRole('INSTRUCTOR')")
    public ResponseEntity<List<User>> getAllTutorsInCourse(@PathVariable Long courseId) {
        log.debug("REST request to get all tutors in course : {}", courseId);
        Course course = courseRepository.findByIdElseThrow(courseId);
        return courseService.getAllUsersInGroup(course, course.getTeachingAssistantGroupName());
    }

    /**
     * GET /courses/:courseId/editors : Returns all users that belong to the editor group of the course
     *
     * @param courseId the id of the course
     * @return list of users with status 200 (OK)
     */
    @GetMapping("courses/{courseId}/editors")
    @PreAuthorize("hasRole('INSTRUCTOR')")
    public ResponseEntity<List<User>> getAllEditorsInCourse(@PathVariable Long courseId) {
        log.debug("REST request to get all editors in course : {}", courseId);
        Course course = courseRepository.findByIdElseThrow(courseId);
        return courseService.getAllUsersInGroup(course, course.getEditorGroupName());
    }

    /**
     * GET /courses/:courseId/instructors : Returns all users that belong to the instructor group of the course
     *
     * @param courseId the id of the course
     * @return list of users with status 200 (OK)
     */
    @GetMapping("courses/{courseId}/instructors")
    @PreAuthorize("hasRole('INSTRUCTOR')")
    public ResponseEntity<List<User>> getAllInstructorsInCourse(@PathVariable Long courseId) {
        log.debug("REST request to get all instructors in course : {}", courseId);
        Course course = courseRepository.findByIdElseThrow(courseId);
        return courseService.getAllUsersInGroup(course, course.getInstructorGroupName());
    }

    /**
     * GET /courses/:courseId/search-users : search users for a given course within all groups.
     *
     * @param courseId   the id of the course for which to search users
     * @param nameOfUser the name by which to search users
     * @return the ResponseEntity with status 200 (OK) and with body all users
     */
    @GetMapping("courses/{courseId}/search-other-users")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<List<User>> searchOtherUsersInCourse(@PathVariable long courseId, @RequestParam("nameOfUser") String nameOfUser) {
        Course course = courseRepository.findByIdElseThrow(courseId);
        authCheckService.checkHasAtLeastRoleInCourseElseThrow(Role.STUDENT, course, null);

        // restrict result size by only allowing reasonable searches
        if (nameOfUser.length() < 3) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Query param 'name' must be three characters or longer.");
        }

        return ResponseEntity.ok().body(courseService.searchOtherUsersNameInCourse(course, nameOfUser));
    }

    /**
     * GET /courses/:courseId/title : Returns the title of the course with the given id
     *
     * @param courseId the id of the course
     * @return the title of the course wrapped in an ResponseEntity or 404 Not Found if no course with that id exists
     */
    @GetMapping("courses/{courseId}/title")
    @PreAuthorize("hasRole('USER')")
    @ResponseBody
    public ResponseEntity<String> getCourseTitle(@PathVariable Long courseId) {
        final var title = courseRepository.getCourseTitle(courseId);
        return title == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(title);
    }

    /**
     * Post /courses/:courseId/students/:studentLogin : Add the given user to the students of the course so that the student can access the course
     *
     * @param courseId     the id of the course
     * @param studentLogin the login of the user who should get student access
     * @return empty ResponseEntity with status 200 (OK) or with status 404 (Not Found)
     */
    @PostMapping("courses/{courseId}/students/{studentLogin:" + Constants.LOGIN_REGEX + "}")
    @PreAuthorize("hasRole('INSTRUCTOR')")
    public ResponseEntity<Void> addStudentToCourse(@PathVariable Long courseId, @PathVariable String studentLogin) {
        log.debug("REST request to add {} as student to course : {}", studentLogin, courseId);
        var course = courseRepository.findByIdElseThrow(courseId);
        return addUserToCourseGroup(studentLogin, userRepository.getUserWithGroupsAndAuthorities(), course, course.getStudentGroupName(), Role.STUDENT);
    }

    /**
     * Post /courses/:courseId/tutors/:tutorLogin : Add the given user to the tutors of the course so that the student can access the course administration
     *
     * @param courseId   the id of the course
     * @param tutorLogin the login of the user who should get tutor access
     * @return empty ResponseEntity with status 200 (OK) or with status 404 (Not Found)
     */
    @PostMapping("courses/{courseId}/tutors/{tutorLogin:" + Constants.LOGIN_REGEX + "}")
    @PreAuthorize("hasRole('INSTRUCTOR')")
    public ResponseEntity<Void> addTutorToCourse(@PathVariable Long courseId, @PathVariable String tutorLogin) {
        log.debug("REST request to add {} as tutors to course : {}", tutorLogin, courseId);
        var course = courseRepository.findByIdElseThrow(courseId);
        return addUserToCourseGroup(tutorLogin, userRepository.getUserWithGroupsAndAuthorities(), course, course.getTeachingAssistantGroupName(), Role.TEACHING_ASSISTANT);
    }

    /**
     * Post /courses/:courseId/editors/:editorLogin : Add the given user to the editors of the course so that the student can access the course administration
     *
     * @param courseId    the id of the course
     * @param editorLogin the login of the user who should get editor access
     * @return empty ResponseEntity with status 200 (OK) or with status 404 (Not Found)
     */
    @PostMapping("courses/{courseId}/editors/{editorLogin:" + Constants.LOGIN_REGEX + "}")
    @PreAuthorize("hasRole('INSTRUCTOR')")
    public ResponseEntity<Void> addEditorToCourse(@PathVariable Long courseId, @PathVariable String editorLogin) {
        log.debug("REST request to add {} as editors to course : {}", editorLogin, courseId);
        Course course = courseRepository.findByIdElseThrow(courseId);
        courseService.checkIfEditorGroupsNeedsToBeCreated(course);
        return addUserToCourseGroup(editorLogin, userRepository.getUserWithGroupsAndAuthorities(), course, course.getEditorGroupName(), Role.EDITOR);
    }

    /**
     * Post /courses/:courseId/instructors/:instructorLogin : Add the given user to the instructors of the course so that the student can access the course administration
     *
     * @param courseId        the id of the course
     * @param instructorLogin the login of the user who should get instructors access
     * @return empty ResponseEntity with status 200 (OK) or with status 404 (Not Found)
     */
    @PostMapping("courses/{courseId}/instructors/{instructorLogin:" + Constants.LOGIN_REGEX + "}")
    @PreAuthorize("hasRole('INSTRUCTOR')")
    public ResponseEntity<Void> addInstructorToCourse(@PathVariable Long courseId, @PathVariable String instructorLogin) {
        log.debug("REST request to add {} as instructors to course : {}", instructorLogin, courseId);
        var course = courseRepository.findByIdElseThrow(courseId);
        return addUserToCourseGroup(instructorLogin, userRepository.getUserWithGroupsAndAuthorities(), course, course.getInstructorGroupName(), Role.INSTRUCTOR);
    }

    /**
     * adds the userLogin to the group (student, tutors or instructors) of the given course
     *
     * @param userLogin         the user login of the student, tutor or instructor who should be added to the group
     * @param instructorOrAdmin the user who initiates this request who must be an instructor of the given course or an admin
     * @param course            the course which is only passes to check if the instructorOrAdmin is an instructor of the course
     * @param group             the group to which the userLogin should be added
     * @param role              the role which should be added
     * @return empty ResponseEntity with status 200 (OK) or with status 404 (Not Found) or with status 403 (Forbidden)
     */
    @NotNull
    public ResponseEntity<Void> addUserToCourseGroup(String userLogin, User instructorOrAdmin, Course course, String group, Role role) {
        if (authCheckService.isAtLeastInstructorInCourse(course, instructorOrAdmin)) {
            Optional<User> userToAddToGroup = userRepository.findOneWithGroupsAndAuthoritiesByLogin(userLogin);
            if (userToAddToGroup.isEmpty()) {
                throw new EntityNotFoundException("User", userLogin);
            }
            courseService.addUserToGroup(userToAddToGroup.get(), group, role);
            return ResponseEntity.ok().body(null);
        } else {
            throw new AccessForbiddenException();
        }
    }

    /**
     * DELETE /courses/:courseId/students/:studentLogin : Remove the given user from the students of the course so that the student cannot access the course anymore
     *
     * @param courseId     the id of the course
     * @param studentLogin the login of the user who should lose student access
     * @return empty ResponseEntity with status 200 (OK) or with status 404 (Not Found)
     */
    @DeleteMapping("courses/{courseId}/students/{studentLogin:" + Constants.LOGIN_REGEX + "}")
    @PreAuthorize("hasRole('INSTRUCTOR')")
    public ResponseEntity<Void> removeStudentFromCourse(@PathVariable Long courseId, @PathVariable String studentLogin) {
        log.debug("REST request to remove {} as student from course : {}", studentLogin, courseId);
        var course = courseRepository.findByIdElseThrow(courseId);
        return removeUserFromCourseGroup(studentLogin, userRepository.getUserWithGroupsAndAuthorities(), course, course.getStudentGroupName(), Role.STUDENT);
    }

    /**
     * DELETE /courses/:courseId/tutors/:tutorsLogin : Remove the given user from the tutors of the course so that the tutors cannot access the course administration anymore
     *
     * @param courseId   the id of the course
     * @param tutorLogin the login of the user who should lose student access
     * @return empty ResponseEntity with status 200 (OK) or with status 404 (Not Found)
     */
    @DeleteMapping("courses/{courseId}/tutors/{tutorLogin:" + Constants.LOGIN_REGEX + "}")
    @PreAuthorize("hasRole('INSTRUCTOR')")
    public ResponseEntity<Void> removeTutorFromCourse(@PathVariable Long courseId, @PathVariable String tutorLogin) {
        log.debug("REST request to remove {} as tutor from course : {}", tutorLogin, courseId);
        var course = courseRepository.findByIdElseThrow(courseId);
        return removeUserFromCourseGroup(tutorLogin, userRepository.getUserWithGroupsAndAuthorities(), course, course.getTeachingAssistantGroupName(), Role.TEACHING_ASSISTANT);
    }

    /**
     * DELETE /courses/:courseId/editors/:editorsLogin : Remove the given user from the editors of the course so that the editors cannot access the course administration anymore
     *
     * @param courseId    the id of the course
     * @param editorLogin the login of the user who should lose student access
     * @return empty ResponseEntity with status 200 (OK) or with status 404 (Not Found)
     */
    @DeleteMapping("courses/{courseId}/editors/{editorLogin:" + Constants.LOGIN_REGEX + "}")
    @PreAuthorize("hasRole('INSTRUCTOR')")
    public ResponseEntity<Void> removeEditorFromCourse(@PathVariable Long courseId, @PathVariable String editorLogin) {
        log.debug("REST request to remove {} as editor from course : {}", editorLogin, courseId);
        var course = courseRepository.findByIdElseThrow(courseId);
        return removeUserFromCourseGroup(editorLogin, userRepository.getUserWithGroupsAndAuthorities(), course, course.getEditorGroupName(), Role.EDITOR);
    }

    /**
     * DELETE /courses/:courseId/instructors/:instructorLogin : Remove the given user from the instructors of the course so that the instructor cannot access the course
     * administration anymore
     *
     * @param courseId        the id of the course
     * @param instructorLogin the login of the user who should lose student access
     * @return empty ResponseEntity with status 200 (OK) or with status 404 (Not Found)
     */
    @DeleteMapping("courses/{courseId}/instructors/{instructorLogin:" + Constants.LOGIN_REGEX + "}")
    @PreAuthorize("hasRole('INSTRUCTOR')")
    public ResponseEntity<Void> removeInstructorFromCourse(@PathVariable Long courseId, @PathVariable String instructorLogin) {
        log.debug("REST request to remove {} as instructor from course : {}", instructorLogin, courseId);
        var course = courseRepository.findByIdElseThrow(courseId);
        return removeUserFromCourseGroup(instructorLogin, userRepository.getUserWithGroupsAndAuthorities(), course, course.getInstructorGroupName(), Role.INSTRUCTOR);
    }

    /**
     * removes the userLogin from the group (student, tutors or instructors) of the given course
     *
     * @param userLogin         the user login of the student, tutor or instructor who should be removed from the group
     * @param instructorOrAdmin the user who initiates this request who must be an instructor of the given course or an admin
     * @param course            the course which is only passes to check if the instructorOrAdmin is an instructor of the course
     * @param group             the group from which the userLogin should be removed
     * @param role              the role which should be removed
     * @return empty ResponseEntity with status 200 (OK) or with status 404 (Not Found) or with status 403 (Forbidden)
     */
    @NotNull
    public ResponseEntity<Void> removeUserFromCourseGroup(String userLogin, User instructorOrAdmin, Course course, String group, Role role) {
        if (!authCheckService.isAtLeastInstructorInCourse(course, instructorOrAdmin)) {
            throw new AccessForbiddenException();
        }
        Optional<User> userToRemoveFromGroup = userRepository.findOneWithGroupsAndAuthoritiesByLogin(userLogin);
        if (userToRemoveFromGroup.isEmpty()) {
            throw new EntityNotFoundException("User", userLogin);
        }
        courseService.removeUserFromGroup(userToRemoveFromGroup.get(), group, role);
        return ResponseEntity.ok().body(null);
    }

    /**
     * GET /courses/{courseId}/management-detail : Gets the data needed for the course management detail view
     *
     * @param courseId the id of the course
     * @return the ResponseEntity with status 200 (OK) and the body, or with status 404 (Not Found)
     */
    @GetMapping("courses/{courseId}/management-detail")
    @PreAuthorize("hasRole('TA')")
    public ResponseEntity<CourseManagementDetailViewDTO> getCourseDTOForDetailView(@PathVariable Long courseId) {
        Course course = courseRepository.findByIdElseThrow(courseId);
        authCheckService.checkHasAtLeastRoleInCourseElseThrow(Role.TEACHING_ASSISTANT, course, null);
        CourseManagementDetailViewDTO managementDetailViewDTO = courseService.getStatsForDetailView(course);
        return ResponseEntity.ok(managementDetailViewDTO);
    }

    /**
     * GET /courses/:courseId/statistics : Get the active students for this particular course
     *
     * @param courseId    the id of the course
     * @param periodIndex an index indicating which time period, 0 is current week, -1 is one week in the past, -2 is two weeks in the past ...
     * @return the ResponseEntity with status 200 (OK) and the data in body, or status 404 (Not Found)
     */
    @GetMapping("courses/{courseId}/statistics")
    @PreAuthorize("hasRole('TA')")
    public ResponseEntity<List<Integer>> getActiveStudentsForCourseDetailView(@PathVariable Long courseId, @RequestParam Long periodIndex) {
        var course = courseRepository.findByIdElseThrow(courseId);
        authCheckService.checkHasAtLeastRoleInCourseElseThrow(Role.TEACHING_ASSISTANT, course, null);
        var exerciseIds = exerciseRepository.findAllIdsByCourseId(courseId);
        var chartEndDate = courseService.determineEndDateForActiveStudents(course);
        var spanEndDate = chartEndDate.plusWeeks(17 * periodIndex);
        var returnedSpanSize = courseService.determineTimeSpanSizeForActiveStudents(course, spanEndDate, 17);
        var activeStudents = courseService.getActiveStudents(exerciseIds, periodIndex, 17, chartEndDate);
        // We omit data concerning the time before the start date
        return ResponseEntity.ok(activeStudents.subList(activeStudents.size() - returnedSpanSize, activeStudents.size()));
    }

    /**
     * GET /courses/:courseId/statistics-lifetime-overview : Get the active students for this particular course over its whole lifetime
     *
     * @param courseId the id of the course
     * @return the ResponseEntity with status 200 (OK) and the data in body, or status 404 (Not Found)
     */
    @GetMapping("courses/{courseId}/statistics-lifetime-overview")
    @PreAuthorize("hasRole('TA')")
    public ResponseEntity<List<Integer>> getActiveStudentsForCourseLiveTime(@PathVariable Long courseId) {
        authCheckService.checkHasAtLeastRoleInCourseElseThrow(Role.TEACHING_ASSISTANT, courseRepository.findByIdElseThrow(courseId), null);
        var exerciseIds = exerciseRepository.findAllIdsByCourseId(courseId);
        var course = courseRepository.findByIdElseThrow(courseId);
        if (course.getStartDate() == null) {
            throw new IllegalArgumentException("Course does not contain start date");
        }
        var endDate = courseService.determineEndDateForActiveStudents(course);
        var returnedSpanSize = courseService.calculateWeeksBetweenDates(course.getStartDate(), endDate);
        var activeStudents = courseService.getActiveStudents(exerciseIds, 0, Math.toIntExact(returnedSpanSize), endDate);
        return ResponseEntity.ok(activeStudents);
    }

    /**
     * POST /courses/:courseId/:courseGroup : Add multiple users to the user group of the course so that they can access the course
     * The passed list of UserDTOs must include the registration number (the other entries are currently ignored and can be left out)
     * Note: registration based on other user attributes (e.g. email, name, login) is currently NOT supported
     * <p>
     * This method first tries to find the student in the internal Artemis user database (because the user is most probably already using Artemis).
     * In case the user cannot be found, we additionally search the (TUM) LDAP in case it is configured properly.
     *
     * @param courseId    the id of the course
     * @param studentDtos the list of students (with at least registration number) who should get access to the course
     * @param courseGroup the group, the user has to be added to, either 'students', 'tutors', 'instructors' or 'editors'
     * @return the list of students who could not be registered for the course, because they could NOT be found in the Artemis database and could NOT be found in the TUM LDAP
     */
    @PostMapping("courses/{courseId}/{courseGroup}")
    @PreAuthorize("hasRole('INSTRUCTOR')")
    public ResponseEntity<List<StudentDTO>> addUsersToCourseGroup(@PathVariable Long courseId, @PathVariable String courseGroup, @RequestBody List<StudentDTO> studentDtos) {
        authCheckService.checkHasAtLeastRoleInCourseElseThrow(Role.INSTRUCTOR, courseRepository.findByIdElseThrow(courseId), null);
        log.debug("REST request to add {} as {} to course {}", studentDtos, courseGroup, courseId);
        List<StudentDTO> notFoundStudentsDtos = courseService.registerUsersForCourseGroup(courseId, studentDtos, courseGroup);
        return ResponseEntity.ok().body(notFoundStudentsDtos);
    }
}
