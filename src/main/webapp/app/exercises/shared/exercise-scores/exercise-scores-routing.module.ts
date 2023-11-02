import { RouterModule, Routes } from '@angular/router';
import { ExerciseScoresComponent } from 'app/exercises/shared/exercise-scores/exercise-scores.component';
import { UserRouteAccessService } from 'app/core/auth/user-route-access-service';
import { NgModule } from '@angular/core';
import { Authority } from 'app/shared/constants/authority.constants';

const routes: Routes = [
    ...['modeling', 'quiz', 'text', 'file-upload'].map((exerciseType) => {
        return {
            path: ':courseId/' + exerciseType + '-exercises/:exerciseId/scores',
            component: ExerciseScoresComponent,
            data: {
                authorities: [Authority.ADMIN, Authority.INSTRUCTOR, Authority.EDITOR, Authority.TA],
                pageTitle: 'artemisApp.instructorDashboard.exerciseDashboard',
            },
            canActivate: [UserRouteAccessService],
        };
    }),
];

@NgModule({
    imports: [RouterModule.forChild(routes)],
    exports: [RouterModule],
})
export class ArtemisExerciseScoresRoutingModule {}
