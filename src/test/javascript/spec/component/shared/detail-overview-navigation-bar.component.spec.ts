import { ComponentFixture, TestBed } from '@angular/core/testing';
import { DetailOverviewNavigationBarComponent } from 'app/shared/detail-overview-navigation-bar/detail-overview-navigation-bar.component';
import { TranslatePipeMock } from '../../helpers/mocks/service/mock-translate.service';

const sectionHeadlines = {
    general: 'some.translation.key',
    grading: 'another.translation.key',
};

const expectedSectionHeadlinesArray = [
    { id: 'general', translationKey: sectionHeadlines.general },
    { id: 'grading', translationKey: sectionHeadlines.grading },
];

const headlineToScrollInto = {
    scrollIntoView: jest.fn(),
} as any as HTMLElement;

describe('DetailOverviewNavigationBar', () => {
    let component: DetailOverviewNavigationBarComponent;
    let fixture: ComponentFixture<DetailOverviewNavigationBarComponent>;

    let getElementByIdSpy: jest.SpyInstance;

    beforeEach(() => {
        TestBed.configureTestingModule({
            imports: [],
            declarations: [DetailOverviewNavigationBarComponent, TranslatePipeMock],
            providers: [],
        })
            .compileComponents()
            .then(() => {
                getElementByIdSpy = jest.spyOn(document, 'getElementById').mockReturnValue(headlineToScrollInto);
            });

        fixture = TestBed.createComponent(DetailOverviewNavigationBarComponent);
        component = fixture.componentInstance;
    });

    it('should initialize', () => {
        component.sectionHeadlines = sectionHeadlines;
        fixture.detectChanges();
        expect(component.sectionHeadlinesArray).toEqual(expectedSectionHeadlinesArray);
        expect(DetailOverviewNavigationBarComponent).not.toBeNull();
    });

    it('should scroll into view', () => {
        const scrollIntroViewSpy = jest.spyOn(headlineToScrollInto, 'scrollIntoView');
        component.sectionHeadlines = sectionHeadlines;
        component.scrollToView('general');
        expect(getElementByIdSpy).toHaveBeenCalledWith('general');
        expect(scrollIntroViewSpy).toHaveBeenCalledOnce();
    });
});
