package de.tum.in.www1.artemis.service;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import de.tum.in.www1.artemis.domain.User;
import de.tum.in.www1.artemis.domain.quiz.QuizExamSubmission;
import de.tum.in.www1.artemis.domain.quiz.QuizExercise;
import de.tum.in.www1.artemis.repository.QuizExamSubmissionRepository;

@Service
public class QuizExamSubmissionService extends AbstractQuizSubmissionService<QuizExamSubmission> {

    private final Logger log = LoggerFactory.getLogger(QuizExamSubmissionService.class);

    private final QuizExamSubmissionRepository quizExamSubmissionRepository;

    public QuizExamSubmissionService(QuizExamSubmissionRepository quizExamSubmissionRepository, SubmissionVersionService submissionVersionService) {
        super(submissionVersionService);
        this.quizExamSubmissionRepository = quizExamSubmissionRepository;
    }

    /**
     * Return the list of quiz submission of the given exam id
     *
     * @param examId the exam id of which the submissions belong to
     * @return the list of quiz submission
     */
    public List<QuizExamSubmission> getAllWithStudentExamAndResultByExamId(Long examId) {
        return quizExamSubmissionRepository.findAllWithStudentExamAndResultByExamId(examId);
    }

    /**
     * Save the quiz submission to the database
     *
     * @param quizExercise the quiz of which the quiz submission corresponds to
     * @param submission   the quiz submission to be saved
     * @param user         the user by which the submission was made (not used in this method implementation)
     * @return QuizExamSubmission the quiz submission that is saved
     */
    @Override
    protected QuizExamSubmission save(QuizExercise quizExercise, QuizExamSubmission submission, User user) {
        QuizExamSubmission savedQuizSubmission = quizExamSubmissionRepository.save(submission);
        log.debug("submit exam quiz finished: {}", savedQuizSubmission);
        return savedQuizSubmission;
    }
}
