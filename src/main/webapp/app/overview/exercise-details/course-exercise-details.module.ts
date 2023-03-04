import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { FontAwesomeModule } from '@fortawesome/angular-fontawesome';

import { ArtemisComplaintsModule } from 'app/complaints/complaints.module';
import { UserRouteAccessService } from 'app/core/auth/user-route-access-service';
import { ArtemisModelingEditorModule } from 'app/exercises/modeling/shared/modeling-editor.module';
import { ArtemisProgrammingExerciseManagementModule } from 'app/exercises/programming/manage/programming-exercise-management.module';
import { ArtemisProgrammingExerciseInstructionsRenderModule } from 'app/exercises/programming/shared/instructions-render/programming-exercise-instructions-render.module';
import { ArtemisHeaderExercisePageWithDetailsModule } from 'app/exercises/shared/exercise-headers/exercise-headers.module';
import { ArtemisExerciseHintParticipationModule } from 'app/exercises/shared/exercise-hint/participate/exercise-hint-participation.module';
import { RatingModule } from 'app/exercises/shared/rating/rating.module';
import { ArtemisResultModule } from 'app/exercises/shared/result/result.module';
import { OrionCourseExerciseDetailsComponent } from 'app/orion/participation/orion-course-exercise-details.component';
import { ArtemisCourseExerciseRowModule } from 'app/overview/course-exercises/course-exercise-row.module';
import { CourseExerciseDetailsComponent } from 'app/overview/exercise-details/course-exercise-details.component';
import { ArtemisExerciseButtonsModule } from 'app/overview/exercise-details/exercise-buttons.module';
import { LtiInitializerModalComponent } from 'app/overview/exercise-details/lti-initializer-modal.component';
import { LtiInitializerComponent } from 'app/overview/exercise-details/lti-initializer.component';
import { SubmissionResultStatusModule } from 'app/overview/submission-result-status.module';
import { ArtemisSharedComponentModule } from 'app/shared/components/shared-component.module';
import { Authority } from 'app/shared/constants/authority.constants';
import { FeatureToggleModule } from 'app/shared/feature-toggle/feature-toggle.module';
import { ArtemisMarkdownModule } from 'app/shared/markdown.module';
import { isOrion } from 'app/shared/orion/orion';
import { OrionModule } from 'app/shared/orion/orion.module';
import { ArtemisSharedPipesModule } from 'app/shared/pipes/shared-pipes.module';
import { ArtemisSharedModule } from 'app/shared/shared.module';
import { ArtemisSidePanelModule } from 'app/shared/side-panel/side-panel.module';

const routes: Routes = [
    {
        path: '',
        component: !isOrion ? CourseExerciseDetailsComponent : OrionCourseExerciseDetailsComponent,
        data: {
            authorities: [Authority.USER],
            pageTitle: 'overview.exercise',
        },
        canActivate: [UserRouteAccessService],
        children: [
            {
                path: '',
                pathMatch: 'full',
                loadChildren: () => import('../discussion-section/discussion-section.module').then((m) => m.DiscussionSectionModule),
            },
        ],
    },
];

@NgModule({
    imports: [
        ArtemisExerciseButtonsModule,
        ArtemisCourseExerciseRowModule,
        ArtemisSharedModule,
        ArtemisSharedComponentModule,
        ArtemisSharedPipesModule,
        ArtemisResultModule,
        ArtemisSidePanelModule,
        ArtemisHeaderExercisePageWithDetailsModule,
        OrionModule,
        ArtemisComplaintsModule,
        FeatureToggleModule,
        FontAwesomeModule,
        RatingModule,
        ArtemisProgrammingExerciseInstructionsRenderModule,
        RouterModule.forChild(routes),
        ArtemisModelingEditorModule,
        ArtemisMarkdownModule,
        SubmissionResultStatusModule,
        ArtemisProgrammingExerciseManagementModule,
        ArtemisExerciseHintParticipationModule,
    ],
    declarations: [CourseExerciseDetailsComponent, OrionCourseExerciseDetailsComponent, LtiInitializerComponent, LtiInitializerModalComponent],
    exports: [CourseExerciseDetailsComponent, OrionCourseExerciseDetailsComponent],
})
export class CourseExerciseDetailsModule {}
