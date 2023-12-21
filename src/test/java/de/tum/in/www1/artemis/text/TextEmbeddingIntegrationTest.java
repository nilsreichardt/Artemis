package de.tum.in.www1.artemis.text;

import de.tum.in.www1.artemis.domain.TextEmbedding;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class TextEmbeddingIntegrationTest {

    @Test
    void testTextEmbedding() {
        var vector = new float[]{1.5f, 2.5f};

        TextEmbedding textEmbedding = new TextEmbedding();
        textEmbedding.setId("id");
        textEmbedding.setVector(vector);

        assertThat(textEmbedding.getId()).isEqualTo("id");
        assertThat(textEmbedding.getVector()).isEqualTo(vector);
    }

}
