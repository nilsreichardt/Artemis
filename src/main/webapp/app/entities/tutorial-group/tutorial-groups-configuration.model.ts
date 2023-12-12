import { BaseEntity } from 'app/shared/model/base-entity';
import { Course } from 'app/entities/course.model';
import dayjs from 'dayjs/esm';
import { TutorialGroupFreeDay } from './tutorial-group-free-day.model';

export class TutorialGroupsConfiguration implements BaseEntity {
    public id?: number;
    public course?: Course;
    public tutorialPeriodStartInclusive?: dayjs.Dayjs;
    public tutorialPeriodEndInclusive?: dayjs.Dayjs;
    public tutorialGroupFreePeriods?: TutorialGroupFreeDay[];
    public useTutorialGroupChannels?: boolean;
    public usePublicTutorialGroupChannels?: boolean;
}
