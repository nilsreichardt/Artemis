import { ExerciseType, IncludedInOverallScore } from 'app/entities/exercise.model';
import { QuizConfiguration } from 'app/entities/quiz/quiz-configuration.model';
import { ExerciseGroup } from 'app/entities/exercise-group.model';
import { QuizQuestion } from 'app/entities/quiz/quiz-question.model';
import { AbstractQuizSubmission } from 'app/entities/quiz/abstract-quiz-exam-submission.model';
import { SubmissionExerciseType } from 'app/entities/submission.model';

export class QuizExam implements QuizConfiguration {
    public id?: number;
    public type: ExerciseType;
    public exerciseGroup?: ExerciseGroup;
    public quizQuestions?: QuizQuestion[];
    public randomizeQuestionOrder?: boolean;
    public title?: string;
    public maxPoints?: number;
    public includedInOverallScore?: IncludedInOverallScore;
    public submission?: AbstractQuizSubmission;

    constructor() {
        this.id = 0;
        this.type = ExerciseType.QUIZ;
        this.exerciseGroup = new ExerciseGroup();
        this.includedInOverallScore = IncludedInOverallScore.INCLUDED_COMPLETELY;
        this.submission = { submissionExerciseType: SubmissionExerciseType.QUIZ };
    }
}
