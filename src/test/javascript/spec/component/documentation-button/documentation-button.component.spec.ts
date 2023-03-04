import { ComponentFixture, TestBed } from '@angular/core/testing';
import { FaIconComponent } from '@fortawesome/angular-fontawesome';
import { NgbTooltip } from '@ng-bootstrap/ng-bootstrap';
import { MockComponent, MockDirective, MockPipe } from 'ng-mocks';

import { DocumentationButtonComponent, DocumentationType } from 'app/shared/components/documentation-button/documentation-button.component';
import { ArtemisTranslatePipe } from 'app/shared/pipes/artemis-translate.pipe';

describe('DocumentationButtonComponent', () => {
    let fixture: ComponentFixture<DocumentationButtonComponent>;
    let comp: DocumentationButtonComponent;

    beforeEach(() => {
        TestBed.configureTestingModule({
            imports: [MockDirective(NgbTooltip)],
            declarations: [DocumentationButtonComponent, MockPipe(ArtemisTranslatePipe), MockComponent(FaIconComponent)],
            providers: [],
            schemas: [],
        })
            .compileComponents()
            .then(() => {
                fixture = TestBed.createComponent(DocumentationButtonComponent);
                comp = fixture.componentInstance;
                comp.type = DocumentationType.Course;
            });
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    it('should initialize', () => {
        fixture.detectChanges();
        expect(comp).not.toBeNull();
    });

    it('should return the correct translation string', () => {
        fixture.detectChanges();

        const translationString = comp.getTooltipForType();
        expect(translationString).toBe('artemisApp.documentationLinks.course');
    });

    it('should open the correct url', () => {
        const mockedOpen = jest.fn();
        const originalOpen = window.open;
        window.open = mockedOpen;

        comp.openDocumentation();
        expect(mockedOpen).toHaveBeenCalledWith('https://docs.artemis.cit.tum.de/user/courses/customizable/', expect.anything());

        window.open = originalOpen;
    });
});
