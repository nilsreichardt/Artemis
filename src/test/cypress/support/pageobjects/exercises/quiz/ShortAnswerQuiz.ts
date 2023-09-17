import { POST, QUIZ_API_EXERCISE_BASE } from '../../../constants';

export class ShortAnswerQuiz {
    getQuizBody() {
        return cy.get('#question0').children().first();
    }

    typeAnswer(line: number, column: number, quizQuestionId: number, answer: string) {
        this.getQuizBody().find(`#solution-${line}-${column}-${quizQuestionId}`).type(answer);
    }

    submit() {
        cy.intercept(POST, QUIZ_API_EXERCISE_BASE + '*/submissions/live').as('createQuizExercise');
        cy.get('#submit-quiz').click();
        return cy.wait('@createQuizExercise');
    }
}
