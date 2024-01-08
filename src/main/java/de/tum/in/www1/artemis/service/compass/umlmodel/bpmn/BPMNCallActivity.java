package de.tum.in.www1.artemis.service.compass.umlmodel.bpmn;

import java.io.Serializable;
import java.util.Objects;

import de.tum.in.www1.artemis.service.compass.strategy.NameSimilarity;
import de.tum.in.www1.artemis.service.compass.umlmodel.Similarity;
import de.tum.in.www1.artemis.service.compass.umlmodel.UMLElement;

/**
 * Represents a BPMN call activity
 */
public class BPMNCallActivity extends UMLElement implements Serializable {

    public static final String BPMN_CALL_ACTIVITY_TYPE = "BPMNCallActivity";

    private final String name;

    /**
     * Construct an instance of the BPMNCallActivity class
     *
     * @param name          The name of the constructed call activity
     * @param jsonElementID The JSON element ID of the constructed call activity
     */
    public BPMNCallActivity(String name, String jsonElementID) {
        super(jsonElementID);

        this.name = name;
    }

    /**
     * Calculate the similarity between the element and another given UML Element
     *
     * @param reference the reference object that should be compared to this object
     * @return A similarity score between 0 and 1
     */
    @Override
    public double similarity(Similarity<UMLElement> reference) {
        if (!(reference instanceof BPMNCallActivity referenceNode)) {
            return 0;
        }

        if (!Objects.equals(getType(), referenceNode.getType())) {
            return 0;
        }

        return NameSimilarity.levenshteinSimilarity(getName(), referenceNode.getName());
    }

    /**
     * Get the name of the element
     *
     * @return The name of the element
     */
    @Override
    public String getName() {
        return this.name;
    }

    /**
     * Get the type of the BPMN element
     *
     * @return The type of BPMN element
     */
    @Override
    public String getType() {
        return BPMN_CALL_ACTIVITY_TYPE;
    }

    /**
     * Get a string representation for the call activity
     *
     * @return A string representation of the call activity
     */
    @Override
    public String toString() {
        return getName();
    }
}
