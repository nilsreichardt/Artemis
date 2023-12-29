import { HttpHeaders, HttpResponse } from '@angular/common/http';
import { HttpTestingController } from '@angular/common/http/testing';
import { ComponentFixture, TestBed, fakeAsync, tick } from '@angular/core/testing';
import { ActivatedRoute, Router } from '@angular/router';
import { Location } from '@angular/common';
import { RouterTestingModule } from '@angular/router/testing';
import { TranslateService } from '@ngx-translate/core';
import { DueDateStat } from 'app/course/dashboards/due-date-stat.model';
import { CourseForDashboardDTO } from 'app/course/manage/course-for-dashboard-dto';
import { CourseManagementService } from 'app/course/manage/course-management.service';
import { CoursesForDashboardDTO } from 'app/course/manage/courses-for-dashboard-dto';
import { Course } from 'app/entities/course.model';
import { Exercise } from 'app/entities/exercise.model';
import { ExerciseService } from 'app/exercises/shared/exercise/exercise.service';
import { GuidedTourService } from 'app/guided-tour/guided-tour.service';
import { CourseCardComponent } from 'app/overview/course-card.component';
import { CourseExerciseRowComponent } from 'app/overview/course-exercises/course-exercise-row.component';
import { CourseExercisesComponent } from 'app/overview/course-exercises/course-exercises.component';
import { CourseRegistrationComponent } from 'app/overview/course-registration/course-registration.component';
import { CoursesComponent } from 'app/overview/courses.component';
import { ArtemisDatePipe } from 'app/shared/pipes/artemis-date.pipe';
import { ArtemisServerDateService } from 'app/shared/server-date.service';
import { MockComponent, MockDirective, MockPipe, MockProvider } from 'ng-mocks';
import { LocalStorageService, SessionStorageService } from 'ngx-webstorage';
import { MockHasAnyAuthorityDirective } from '../../helpers/mocks/directive/mock-has-any-authority.directive';
import { MockSyncStorage } from '../../helpers/mocks/service/mock-sync-storage.service';
import { MockTranslateService } from '../../helpers/mocks/service/mock-translate.service';
import { ArtemisTestModule } from '../../test.module';
import { ArtemisTranslatePipe } from 'app/shared/pipes/artemis-translate.pipe';
import { SortByDirective } from 'app/shared/sort/sort-by.directive';
import { SortDirective } from 'app/shared/sort/sort.directive';
import { AlertService } from 'app/core/util/alert.service';
import { Component } from '@angular/core';
import { of } from 'rxjs';
import dayjs from 'dayjs/esm';
import { Exam } from 'app/entities/exam.model';
import { QuizExercise, QuizMode } from 'app/entities/quiz/quiz-exercise.model';
import { InitializationState } from 'app/entities/participation/participation.model';

const endDate1 = dayjs().add(1, 'days');
const visibleDate1 = dayjs().subtract(1, 'days');
const endDate2 = dayjs().subtract(1, 'days');
const visibleDate2 = dayjs().subtract(2, 'days');
const dueDateStat1: DueDateStat = { inTime: 1, late: 0, total: 1 };
const exercise1: Exercise = {
    id: 5,
    numberOfAssessmentsOfCorrectionRounds: [dueDateStat1],
    studentAssignedTeamIdComputed: false,
    dueDate: dayjs().add(2, 'hours'),
    secondCorrectionEnabled: true,
};
const exercise2: Exercise = {
    id: 6,
    numberOfAssessmentsOfCorrectionRounds: [dueDateStat1],
    studentAssignedTeamIdComputed: false,
    dueDate: dayjs().add(1, 'hours'),
    secondCorrectionEnabled: true,
};
const exercise3: Exercise = {
    id: 7,
    numberOfAssessmentsOfCorrectionRounds: [dueDateStat1],
    studentAssignedTeamIdComputed: false,
    dueDate: dayjs().add(3, 'hours'),
    secondCorrectionEnabled: true,
};
const activeQuiz: QuizExercise = {
    id: 8,
    isActiveQuiz: true,
    quizMode: QuizMode.SYNCHRONIZED,
    studentParticipations: [{ initializationState: InitializationState.INITIALIZED }],
    numberOfAssessmentsOfCorrectionRounds: [],
    secondCorrectionEnabled: false,
    studentAssignedTeamIdComputed: false,
};
const visibleQuiz: QuizExercise = {
    id: 9,
    isActiveQuiz: false,
    visibleToStudents: true,
    quizMode: QuizMode.SYNCHRONIZED,
    numberOfAssessmentsOfCorrectionRounds: [],
    secondCorrectionEnabled: false,
    studentAssignedTeamIdComputed: false,
};

const courseEmpty: Course = {};

const exam1: Exam = { id: 3, endDate: endDate1, visibleDate: visibleDate1, course: courseEmpty };
const exam2: Exam = { id: 4, endDate: endDate2, visibleDate: visibleDate2, course: courseEmpty };
const exams = [exam1, exam2];
const course1: Course = { id: 1, exams, exercises: [exercise1, exercise3] };
const course1Dashboard = { course: course1 } as CourseForDashboardDTO;
const course2: Course = { id: 2, exercises: [exercise2], testCourse: true };
const course2Dashboard = { course: course2 } as CourseForDashboardDTO;
const course3: Course = { id: 3 };
const course4: Course = { id: 4 };
const coursesInDashboard: CourseForDashboardDTO[] = [course1Dashboard, course2Dashboard];
const courses: Course[] = [course1, course2];
const coursesDashboard = { courses: coursesInDashboard } as CoursesForDashboardDTO;

@Component({
    template: '',
})
class DummyComponent {}

describe('CoursesComponent', () => {
    let component: CoursesComponent;
    let fixture: ComponentFixture<CoursesComponent>;
    let courseService: CourseManagementService;
    let serverDateService: ArtemisServerDateService;
    let exerciseService: ExerciseService;
    let router: Router;
    let location: Location;
    let httpMock: HttpTestingController;

    const route = { data: of({ courseId: course1.id }), children: [] } as any as ActivatedRoute;

    beforeEach(() => {
        TestBed.configureTestingModule({
            imports: [ArtemisTestModule, RouterTestingModule.withRoutes([{ path: 'courses/:courseId/exams/:examId', component: DummyComponent }])],
            declarations: [
                CoursesComponent,
                MockDirective(MockHasAnyAuthorityDirective),
                MockPipe(ArtemisTranslatePipe),
                MockDirective(SortDirective),
                MockDirective(SortByDirective),
                MockPipe(ArtemisDatePipe),
                MockComponent(CourseExerciseRowComponent),
                MockComponent(CourseExercisesComponent),
                MockComponent(CourseRegistrationComponent),
                MockComponent(CourseCardComponent),
            ],
            providers: [
                { provide: LocalStorageService, useClass: MockSyncStorage },
                { provide: SessionStorageService, useClass: MockSyncStorage },
                { provide: TranslateService, useClass: MockTranslateService },
                { provide: ActivatedRoute, useValue: route },
                { provide: CourseExerciseRowComponent },
                MockProvider(AlertService),
            ],
        })
            .compileComponents()
            .then(() => {
                fixture = TestBed.createComponent(CoursesComponent);
                component = fixture.componentInstance;
                courseService = TestBed.inject(CourseManagementService);
                location = TestBed.inject(Location);
                TestBed.inject(GuidedTourService);
                serverDateService = TestBed.inject(ArtemisServerDateService);
                TestBed.inject(AlertService);
                exerciseService = TestBed.inject(ExerciseService);
                httpMock = TestBed.inject(HttpTestingController);
                fixture.detectChanges();
            });
        router = TestBed.inject(Router);
    });

    afterEach(() => {
        component.ngOnDestroy();
        jest.restoreAllMocks();
    });

    describe('onInit', () => {
        it('should call loadAndFilterCourses on init', () => {
            const loadAndFilterCoursesSpy = jest.spyOn(component, 'loadAndFilterCourses');

            component.ngOnInit();

            expect(loadAndFilterCoursesSpy).toHaveBeenCalledOnce();
        });

        it('should load courses on init', () => {
            const findAllForDashboardSpy = jest.spyOn(courseService, 'findAllForDashboard');
            const serverDateServiceSpy = jest.spyOn(serverDateService, 'now');
            const findNextRelevantExerciseSpy = jest.spyOn(component, 'findNextRelevantExercise');
            findAllForDashboardSpy.mockReturnValue(of(new HttpResponse({ body: coursesDashboard, headers: new HttpHeaders() })));
            serverDateServiceSpy.mockReturnValue(dayjs());

            component.ngOnInit();

            expect(findAllForDashboardSpy).toHaveBeenCalledOnce();
            expect(findNextRelevantExerciseSpy).toHaveBeenCalledOnce();
            expect(component.courses).toEqual(courses);
            expect(component.nextRelevantExams).toHaveLength(0);
        });

        it('should handle an empty response body correctly when fetching all courses for dashboard', () => {
            const findAllForDashboardSpy = jest.spyOn(courseService, 'findAllForDashboard');

            const req = httpMock.expectOne({ method: 'GET', url: `api/courses/for-dashboard` });
            component.ngOnInit();

            expect(findAllForDashboardSpy).toHaveBeenCalledOnce();
            req.flush(null);
            expect(component.courses).toBeUndefined();
        });

        it('should load exercises on init', () => {
            const mockFunction = (arg1: Exercise[]) => {
                switch (arg1[0].id) {
                    case exercise1.id:
                        return exercise1;
                    case exercise2.id:
                        return exercise2;
                }
            };

            const findAllForDashboardSpy = jest.spyOn(courseService, 'findAllForDashboard');
            const getNextExerciseForHoursSpy = jest.spyOn(exerciseService, 'getNextExerciseForHours').mockImplementation(mockFunction);
            const serverDateServiceSpy = jest.spyOn(serverDateService, 'now');

            findAllForDashboardSpy.mockReturnValue(of(new HttpResponse({ body: coursesDashboard, headers: new HttpHeaders() })));
            serverDateServiceSpy.mockReturnValue(dayjs());

            component.ngOnInit();

            expect(getNextExerciseForHoursSpy).toHaveBeenCalledWith(course1.exercises);
            expect(component.nextRelevantExercise).toEqual(exercise1);
            expect(component.nextRelevantCourse).toEqual(exercise1.course);
        });
    });

    describe('findNextRelevantExercise', () => {
        beforeEach(() => {
            component.courses = [course3, course4];
        });

        it('should show active quiz', () => {
            course3.exercises = [exercise1, exercise2];
            course4.exercises = [activeQuiz, visibleQuiz];
            activeQuiz.course = course4;

            expect(component.findNextRelevantExercise()).toBe(activeQuiz);
        });

        it('should show visible quiz if no active quiz is present', () => {
            course3.exercises = [exercise1, exercise2];
            course4.exercises = [exercise3, visibleQuiz];
            visibleQuiz.course = course4;

            expect(component.findNextRelevantExercise()).toBe(visibleQuiz);
        });

        it('should show exercise with next due date if no quiz is present', () => {
            course3.exercises = [exercise1, exercise2];
            course4.exercises = [exercise3];
            exercise1.course = course3;

            expect(component.findNextRelevantExercise()).toBe(exercise1);
        });

        it('should ignore test course', () => {
            course3.exercises = [exercise1, exercise2];
            course4.exercises = [activeQuiz, visibleQuiz];
            course4.testCourse = true;
            exercise1.course = course3;

            expect(component.findNextRelevantExercise()).toBe(exercise1);

            course4.testCourse = false;
        });
    });

    it('should load next relevant exam', fakeAsync(() => {
        const navigateSpy = jest.spyOn(router, 'navigate');
        component.nextRelevantCourseForExam = course1;
        component.nextRelevantExams = [exam1];
        component.openExam();
        tick();

        expect(navigateSpy).toHaveBeenCalledWith(['courses', 1, 'exams', 3]);
        expect(location.path()).toBe('/courses/1/exams/3');
    }));

    it('should load next relevant exam ignoring test exams', fakeAsync(() => {
        const testExam1 = {
            id: 5,
            startDate: dayjs().add(1, 'hour'),
            endDate: endDate1,
            visibleDate: visibleDate1.subtract(10, 'minutes'),
            course: courseEmpty,
            workingTime: 3600,
            testExam: true,
        };
        const course6 = { id: 3, exams: [testExam1], exercises: [exercise1] };
        const coursesForDashboard = new CoursesForDashboardDTO();
        const courseForDashboard1 = new CourseForDashboardDTO();
        courseForDashboard1.course = course1;
        const courseForDashboard2 = new CourseForDashboardDTO();
        courseForDashboard2.course = course2;
        const courseForDashboard6 = new CourseForDashboardDTO();
        courseForDashboard6.course = course6;
        coursesForDashboard.courses = [courseForDashboard1, courseForDashboard2, courseForDashboard6];

        const findAllForDashboardSpy = jest.spyOn(courseService, 'findAllForDashboard');
        const serverDateServiceSpy = jest.spyOn(serverDateService, 'now');
        const findNextRelevantExerciseSpy = jest.spyOn(component, 'findNextRelevantExercise');
        findAllForDashboardSpy.mockReturnValue(
            of(
                new HttpResponse({
                    body: coursesForDashboard,
                    headers: new HttpHeaders(),
                }),
            ),
        );
        serverDateServiceSpy.mockReturnValue(dayjs());

        component.ngOnInit();
        tick(1000);

        expect(findAllForDashboardSpy).toHaveBeenCalledOnce();
        expect(findNextRelevantExerciseSpy).toHaveBeenCalledOnce();
        expect(component.courses).toEqual([course1, course2, course6]);
        expect(component.nextRelevantExams).toEqual([]);
    }));
});
