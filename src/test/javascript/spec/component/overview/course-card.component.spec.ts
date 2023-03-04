import { ComponentFixture, TestBed } from '@angular/core/testing';
import { PieChartModule } from '@swimlane/ngx-charts';
import dayjs from 'dayjs/esm';
import { MockComponent, MockDirective, MockModule, MockPipe } from 'ng-mocks';

import { MockRouterLinkDirective } from '../../helpers/mocks/directive/mock-router-link.directive';
import { ArtemisTestModule } from '../../test.module';
import { Course } from 'app/entities/course.model';
import { Exercise } from 'app/entities/exercise.model';
import { ProgrammingSubmission } from 'app/entities/programming-submission.model';
import { SubmissionExerciseType } from 'app/entities/submission.model';
import { CourseCardComponent } from 'app/overview/course-card.component';
import { SecuredImageComponent } from 'app/shared/image/secured-image.component';
import { TranslateDirective } from 'app/shared/language/translate.directive';
import { ArtemisTimeAgoPipe } from 'app/shared/pipes/artemis-time-ago.pipe';
import { ArtemisTranslatePipe } from 'app/shared/pipes/artemis-translate.pipe';

describe('CourseCardComponent', () => {
    let fixture: ComponentFixture<CourseCardComponent>;
    let component: CourseCardComponent;
    const submission: ProgrammingSubmission = {
        submissionExerciseType: SubmissionExerciseType.PROGRAMMING,
        id: 3,
        submitted: true,
        results: [{ successful: true }],
    };
    const pastExercise = { id: 1, dueDate: dayjs().subtract(2, 'days') } as Exercise;
    const nextExercise = { id: 2, dueDate: dayjs().add(2, 'days'), studentParticipations: [{ submissions: [submission] }] } as Exercise;
    const secondNextExercise = { id: 3, dueDate: dayjs().add(4, 'days') } as Exercise;
    const course = { id: 1, exercises: [pastExercise, nextExercise, secondNextExercise], lectures: [], exams: [] } as Course;

    beforeEach(() => {
        TestBed.configureTestingModule({
            imports: [ArtemisTestModule, MockModule(PieChartModule)],
            declarations: [
                CourseCardComponent,
                MockPipe(ArtemisTranslatePipe),
                MockPipe(ArtemisTimeAgoPipe),
                MockRouterLinkDirective,
                MockComponent(SecuredImageComponent),
                MockDirective(TranslateDirective),
            ],
        })
            .compileComponents()
            .then(() => {
                fixture = TestBed.createComponent(CourseCardComponent);
                component = fixture.componentInstance;
                component.course = course;
            });
    });

    it('should initialize component', () => {
        fixture.detectChanges();
        expect(component).toBeDefined();
    });

    it('should display the next exercise which is not yet successful', () => {
        fixture.detectChanges();
        component.ngOnChanges();
        expect(component.nextRelevantExercise).toEqual(secondNextExercise);
    });
});
