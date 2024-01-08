import { ComponentFixture, TestBed, fakeAsync, tick } from '@angular/core/testing';
import { Component } from '@angular/core';
import { ArtemisTestModule } from '../test.module';
import { By } from '@angular/platform-browser';
import { ScienceEventType } from 'app/shared/science/science.model';
import { ScienceDirective } from 'app/shared/science/science.direcive';
import { ScienceService } from 'app/shared/science/science.service';

@Component({
    template: '<div [jhiScience]="ScienceEventType.LECTURE__OPEN"></div>',
})
class ScienceDirectiveComponent {
    protected readonly ScienceEventType = ScienceEventType;
}

describe('ScienceDirective', () => {
    let fixture: ComponentFixture<ScienceDirectiveComponent>;
    let scienceService: ScienceService;
    let logEventStub: jest.SpyInstance;

    beforeEach(() => {
        TestBed.configureTestingModule({
            imports: [ArtemisTestModule],
            declarations: [ScienceDirective, ScienceDirectiveComponent],
        })
            .compileComponents()
            .then(() => {
                fixture = TestBed.createComponent(ScienceDirectiveComponent);
                scienceService = TestBed.inject(ScienceService);
                logEventStub = jest.spyOn(scienceService, 'logEvent');
                fixture.detectChanges();
            });
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    it('should log event on click', fakeAsync(() => {
        fixture.whenStable();
        const div = fixture.debugElement.query(By.css('div'));
        expect(div).not.toBeNull();
        div.nativeElement.dispatchEvent(new MouseEvent('click'));
        tick(10);
        expect(logEventStub).toHaveBeenCalledOnce();
    }));
});
