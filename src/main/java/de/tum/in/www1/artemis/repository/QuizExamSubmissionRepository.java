package de.tum.in.www1.artemis.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import de.tum.in.www1.artemis.domain.quiz.QuizExamSubmission;

/**
 * Spring Data JPA repository for the QuizExamSubmission entity.
 */
@Repository
public interface QuizExamSubmissionRepository extends JpaRepository<QuizExamSubmission, Long> {

    /**
     * Get the quiz exam submission with the given id and eagerly load its submitted answers.
     *
     * @param studentExamId the id of the student exam
     * @return the quiz exam submission with the given id and its eagerly loaded submitted answers
     */
    @Query("""
                SELECT DISTINCT qes FROM QuizExamSubmission qes
                LEFT JOIN FETCH qes.submittedAnswers
                WHERE qes.studentExam.id = :#{#studentExamId}
            """)
    Optional<QuizExamSubmission> findWithEagerSubmittedAnswersByStudentExamId(Long studentExamId);

    /**
     * Get the quiz exam submission with the given exam id and eagerly load its submitted answers
     *
     * @param examId the id of the exam
     * @return the quiz exam submission with the given exam id and its eagerly loaded submitted answers
     */
    @Query("""
                SELECT DISTINCT qes
                FROM QuizExamSubmission qes
                WHERE qes.studentExam.exam.id = :#{#examId}
            """)
    List<QuizExamSubmission> findAllByExamId(Long examId);

    /**
     * Get the quiz exam submission with the given exam id and eagerly load its results
     *
     * @param examId the id of the exam
     * @return the quiz exam submission with the given exam id and its eagerly loaded results
     */
    @Query("""
                SELECT DISTINCT qes
                FROM QuizExamSubmission qes
                JOIN FETCH qes.studentExam se
                JOIN FETCH se.exam e
                LEFT JOIN FETCH qes.results
                WHERE qes.studentExam.exam.id = :#{#examId}
            """)
    List<QuizExamSubmission> findAllWithStudentExamAndExamAndResultsByExamId(Long examId);

    /**
     * Get the quiz exam submission with the given exam id and eagerly load submitted answers
     *
     * @param examId the id of the exam
     * @return the quiz exam submission with the given exam id and its eagerly loaded submitted answers
     */
    @Query("""
                SELECT DISTINCT qes
                FROM QuizExamSubmission qes
                LEFT JOIN FETCH qes.submittedAnswers
                WHERE qes.studentExam.exam.id = :#{#examId}
            """)
    List<QuizExamSubmission> findAllWithEagerSubmittedAnswersByExamId(Long examId);
}
