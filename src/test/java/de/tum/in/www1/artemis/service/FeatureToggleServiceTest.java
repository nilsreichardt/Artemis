package de.tum.in.www1.artemis.service;

import de.tum.in.www1.artemis.AbstractSpringIntegrationIndependentTest;
import de.tum.in.www1.artemis.service.feature.Feature;
import de.tum.in.www1.artemis.service.feature.FeatureToggleService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class FeatureToggleServiceTest extends AbstractSpringIntegrationIndependentTest {

    @Autowired
    private FeatureToggleService featureToggleService;

    @AfterEach
    void checkReset() {
        // Verify that the test has reset the state
        // Must be extended if additional features are added
        assertThat(featureToggleService.isFeatureEnabled(Feature.ProgrammingExercises)).isTrue();
        assertThat(featureToggleService.isFeatureEnabled(Feature.LearningPaths)).isTrue();
    }

    @Test
    void testSetFeaturesEnabled() {
        Map<Feature, Boolean> featureStates = new HashMap<>();
        featureStates.put(Feature.ProgrammingExercises, true);
        featureToggleService.updateFeatureToggles(featureStates);
        assertThat(featureToggleService.isFeatureEnabled(Feature.ProgrammingExercises)).isTrue();
    }

    @Test
    void testSetFeaturesDisabled() {
        assertThat(featureToggleService.isFeatureEnabled(Feature.ProgrammingExercises)).isTrue();

        Map<Feature, Boolean> featureStates = new HashMap<>();
        featureStates.put(Feature.ProgrammingExercises, false);
        featureToggleService.updateFeatureToggles(featureStates);
        assertThat(featureToggleService.isFeatureEnabled(Feature.ProgrammingExercises)).isFalse();

        // Reset
        featureToggleService.enableFeature(Feature.ProgrammingExercises);
    }

    @Test
    void testEnableDisableFeature() {
        assertThat(featureToggleService.isFeatureEnabled(Feature.ProgrammingExercises)).isTrue();

        featureToggleService.disableFeature(Feature.ProgrammingExercises);
        assertThat(featureToggleService.isFeatureEnabled(Feature.ProgrammingExercises)).isFalse();

        featureToggleService.enableFeature(Feature.ProgrammingExercises);
        assertThat(featureToggleService.isFeatureEnabled(Feature.ProgrammingExercises)).isTrue();
    }

    @Test
    void testShouldNotEnableTwice() {
        assertThat(featureToggleService.enabledFeatures()).hasSameSizeAs(Feature.values());
        featureToggleService.enableFeature(Feature.ProgrammingExercises);

        // Feature should not be added multiple times
        assertThat(featureToggleService.enabledFeatures()).hasSameSizeAs(Feature.values());
    }

    @Test
    void testShouldNotDisableTwice() {
        featureToggleService.disableFeature(Feature.ProgrammingExercises);

        assertThat(featureToggleService.disabledFeatures()).hasSize(1);
        featureToggleService.disableFeature(Feature.ProgrammingExercises);

        // Feature should not be added multiple times
        assertThat(featureToggleService.disabledFeatures()).hasSize(1);

        // Reset
        featureToggleService.enableFeature(Feature.ProgrammingExercises);
    }
}
