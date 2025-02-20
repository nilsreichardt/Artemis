import { Routes } from '@angular/router';
import { UserRouteAccessService } from 'app/core/auth/user-route-access-service';
import { userManagementRoute } from 'app/admin/user-management/user-management.route';
import { systemNotificationManagementRoute } from 'app/admin/system-notification-management/system-notification-management.route';
import { Authority } from 'app/shared/constants/authority.constants';
import { upcomingExamsAndExercisesRoute } from 'app/admin/upcoming-exams-and-exercises/upcoming-exams-and-exercises.route';
import { AuditsComponent } from 'app/admin/audits/audits.component';
import { ConfigurationComponent } from 'app/admin/configuration/configuration.component';
import { AdminFeatureToggleComponent } from 'app/admin/features/admin-feature-toggle.component';
import { HealthComponent } from 'app/admin/health/health.component';
import { LogsComponent } from 'app/admin/logs/logs.component';
import { StatisticsComponent } from 'app/admin/statistics/statistics.component';
import { DocsComponent } from 'app/admin/docs/docs.component';
import { organizationMgmtRoute } from 'app/admin/organization-management/organization-management.route';
import { MetricsComponent } from 'app/admin/metrics/metrics.component';
import { BuildQueueComponent } from 'app/localci/build-queue/build-queue.component';
import { BuildQueueGuard } from 'app/localci/build-queue/build-queue.guard';
import { ltiConfigurationRoute } from 'app/admin/lti-configuration/lti-configuration.route';

export const adminState: Routes = [
    {
        path: '',
        data: {
            authorities: [Authority.ADMIN],
        },
        canActivate: [UserRouteAccessService],
        children: [
            {
                path: 'audits',
                component: AuditsComponent,
                data: {
                    pageTitle: 'audits.title',
                    defaultSort: 'auditEventDate,desc',
                },
            },
            {
                path: 'configuration',
                component: ConfigurationComponent,
                data: {
                    pageTitle: 'configuration.title',
                },
            },
            {
                path: 'feature-toggles',
                component: AdminFeatureToggleComponent,
                data: {
                    pageTitle: 'featureToggles.title',
                },
            },
            {
                path: 'health',
                component: HealthComponent,
                data: {
                    pageTitle: 'health.title',
                },
            },
            {
                path: 'logs',
                component: LogsComponent,
                data: {
                    pageTitle: 'logs.title',
                },
            },
            {
                path: 'docs',
                component: DocsComponent,
                data: {
                    pageTitle: 'global.menu.admin.apidocs',
                },
            },
            {
                path: 'metrics',
                component: MetricsComponent,
                data: {
                    pageTitle: 'metrics.title',
                },
            },
            {
                path: 'user-statistics',
                component: StatisticsComponent,
                data: {
                    pageTitle: 'statistics.title',
                },
            },
            {
                path: 'build-queue',
                component: BuildQueueComponent,
                data: {
                    pageTitle: 'artemisApp.buildQueue.title',
                },
                canActivate: [BuildQueueGuard],
            },
            {
                path: 'privacy-statement',
                loadChildren: () => import('./legal/legal-update.module').then((module) => module.LegalUpdateModule),
            },
            {
                path: 'imprint',
                loadChildren: () => import('./legal/legal-update.module').then((module) => module.LegalUpdateModule),
            },
            {
                path: 'iris',
                loadChildren: () =>
                    import('../iris/settings/iris-global-settings-update/iris-global-settings-update-routing.module').then(
                        (module) => module.IrisGlobalSettingsUpdateRoutingModule,
                    ),
            },
            ...organizationMgmtRoute,
            ...userManagementRoute,
            ...systemNotificationManagementRoute,
            upcomingExamsAndExercisesRoute,
            ...ltiConfigurationRoute,
        ],
    },
];
