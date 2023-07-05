import { Component, OnDestroy, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { CourseManagementService } from 'app/course/manage/course-management.service';
import { Course } from 'app/entities/course.model';
import { Subject, Subscription } from 'rxjs';
import { LearningPathService } from 'app/course/learning-paths/learning-path.service';
import { debounceTime, finalize, switchMap, tap } from 'rxjs/operators';
import { HttpErrorResponse } from '@angular/common/http';
import { onError } from 'app/shared/util/global.utils';
import { AlertService } from 'app/core/util/alert.service';
import { PageableSearch, SearchResult, SortingOrder } from 'app/shared/table/pageable-table';
import { LearningPathPagingService } from 'app/course/learning-paths/learning-path-paging.service';
import { SortService } from 'app/shared/service/sort.service';
import { LearningPath } from 'app/entities/learning-path.model';
import { faSort } from '@fortawesome/free-solid-svg-icons';

export enum TableColumn {
    ID = 'ID',
    USER_NAME = 'USER_NAME',
    USER_LOGIN = 'USER_LOGIN',
    PROGRESS = 'PROGRESS',
}

@Component({
    selector: 'jhi-learning-path-management',
    templateUrl: './learning-path-management.component.html',
})
export class LearningPathManagementComponent implements OnInit, OnDestroy {
    isLoading = false;

    courseId: number;
    course: Course;

    courseSub: Subscription;

    searchLoading = false;
    readonly column = TableColumn;
    state: PageableSearch = {
        page: 1,
        pageSize: 50,
        searchTerm: '',
        sortingOrder: SortingOrder.ASCENDING,
        sortedColumn: TableColumn.ID,
    };
    content: SearchResult<LearningPath>;
    total = 0;

    private search = new Subject<void>();
    private sort = new Subject<void>();

    // icons
    faSort = faSort;

    constructor(
        private activatedRoute: ActivatedRoute,
        private courseManagementService: CourseManagementService,
        private learningPathService: LearningPathService,
        private alertService: AlertService,
        private pagingService: LearningPathPagingService,
        private sortService: SortService,
    ) {}

    get page(): number {
        return this.state.page;
    }

    set page(page: number) {
        this.setSearchParam({ page });
    }

    get listSorting(): boolean {
        return this.state.sortingOrder === SortingOrder.ASCENDING;
    }

    /**
     * Set the list sorting direction
     *
     * @param ascending {boolean} Ascending order set
     */
    set listSorting(ascending: boolean) {
        const sortingOrder = ascending ? SortingOrder.ASCENDING : SortingOrder.DESCENDING;
        this.setSearchParam({ sortingOrder });
    }

    /**
     * Gives the ID for any item in the table, so that it can be tracked/identified by ngFor
     *
     * @param index The index of the element in the ngFor
     * @param item The item itself
     * @returns The ID of the item
     */
    trackId(index: number, item: LearningPath): number {
        return item.id!;
    }

    get sortedColumn(): string {
        return this.state.sortedColumn;
    }

    set sortedColumn(sortedColumn: string) {
        this.setSearchParam({ sortedColumn });
    }

    get searchTerm(): string {
        return this.state.searchTerm;
    }

    set searchTerm(searchTerm: string) {
        this.state.searchTerm = searchTerm;
        this.search.next();
    }

    ngOnInit(): void {
        this.content = { resultsOnPage: [], numberOfPages: 0 };

        this.activatedRoute.parent!.params.subscribe((params) => {
            this.courseId = +params['courseId'];
            if (this.courseId) {
                this.loadData();
            }
        });
    }

    private loadData() {
        this.isLoading = true;

        this.courseSub = this.courseManagementService.findWithLearningPaths(this.courseId).subscribe((courseResponse) => {
            this.course = courseResponse.body!;

            if (this.course.learningPathsEnabled) {
                this.performSearch(this.sort, 0);
                this.performSearch(this.search, 300);
            }

            this.isLoading = false;
        });
    }

    /**
     * On destroy unsubscribe all subscriptions.
     */
    ngOnDestroy() {
        if (this.courseSub) {
            this.courseSub.unsubscribe();
        }
    }

    enableLearningPaths() {
        this.isLoading = true;
        this.learningPathService
            .enableLearningPaths(this.courseId)
            .pipe(
                finalize(() => {
                    this.isLoading = false;
                }),
            )
            .subscribe({
                next: (res) => {
                    this.course = res.body!;
                },
                error: (res: HttpErrorResponse) => onError(this.alertService, res),
            });
    }

    /**
     * Method to perform the search based on a search subject
     *
     * @param searchSubject The search subject which we use to search.
     * @param debounce The delay we apply to delay the feedback / wait for input
     */
    performSearch(searchSubject: Subject<void>, debounce: number): void {
        searchSubject
            .pipe(
                debounceTime(debounce),
                tap(() => (this.searchLoading = true)),
                switchMap(() => this.pagingService.searchForLearningPaths(this.state, this.courseId)),
            )
            .subscribe((resp) => {
                this.content = resp;
                this.searchLoading = false;
                this.total = resp.numberOfPages * this.state.pageSize;
            });
    }

    sortRows() {
        this.sortService.sortByProperty(this.content.resultsOnPage, this.sortedColumn, this.listSorting);
    }

    private setSearchParam(patch: Partial<PageableSearch>): void {
        Object.assign(this.state, patch);
        this.sort.next();
    }

    /**
     * Callback function when the user navigates through the page results
     *
     * @param pageNumber The current page number
     */
    onPageChange(pageNumber: number) {
        if (pageNumber) {
            this.page = pageNumber;
        }
    }
    viewLearningPath(learningPath: LearningPath) {
        // TODO
    }
}
