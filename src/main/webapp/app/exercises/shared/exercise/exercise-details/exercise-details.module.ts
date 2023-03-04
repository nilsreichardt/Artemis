import { NgModule } from '@angular/core';
import { RouterModule } from '@angular/router';

import { AssessmentInstructionsModule } from 'app/assessment/assessment-instructions/assessment-instructions.module';
import { ArtemisProgrammingExerciseInstructionsRenderModule } from 'app/exercises/programming/shared/instructions-render/programming-exercise-instructions-render.module';
import { ArtemisProgrammingExerciseLifecycleModule } from 'app/exercises/programming/shared/lifecycle/programming-exercise-lifecycle.module';
import { ExerciseDetailsComponent } from 'app/exercises/shared/exercise/exercise-details/exercise-details.component';
import { ArtemisExerciseModule } from 'app/exercises/shared/exercise/exercise.module';
import { ArtemisModePickerModule } from 'app/exercises/shared/mode-picker/mode-picker.module';
import { ExerciseDetailStatisticsComponent } from 'app/exercises/shared/statistics/exercise-detail-statistics.component';
import { ExerciseStatisticsComponent } from 'app/exercises/shared/statistics/exercise-statistics.component';
import { ArtemisChartsModule } from 'app/shared/chart/artemis-charts.module';
import { ArtemisSharedComponentModule } from 'app/shared/components/shared-component.module';
import { ArtemisMarkdownModule } from 'app/shared/markdown.module';
import { ArtemisSharedModule } from 'app/shared/shared.module';

@NgModule({
    imports: [
        ArtemisProgrammingExerciseInstructionsRenderModule,
        ArtemisExerciseModule,
        ArtemisSharedModule,
        ArtemisSharedComponentModule,
        ArtemisModePickerModule,
        AssessmentInstructionsModule,
        RouterModule,
        ArtemisMarkdownModule,
        ArtemisProgrammingExerciseLifecycleModule,
        ArtemisChartsModule,
    ],
    declarations: [ExerciseDetailsComponent, ExerciseDetailStatisticsComponent, ExerciseStatisticsComponent],
    exports: [ExerciseDetailsComponent, ExerciseDetailStatisticsComponent, ExerciseStatisticsComponent],
})
export class ExerciseDetailsModule {}
