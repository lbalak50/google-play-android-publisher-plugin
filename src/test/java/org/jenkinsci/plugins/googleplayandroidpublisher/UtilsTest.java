package org.jenkinsci.plugins.googleplayandroidpublisher;

import com.google.api.client.googleapis.json.GoogleJsonResponseException;
import com.google.api.client.http.HttpHeaders;
import com.google.api.client.http.HttpResponseException;
import com.google.api.services.androidpublisher.model.LocalizedText;
import com.google.api.services.androidpublisher.model.TrackRelease;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import org.jenkinsci.plugins.googleplayandroidpublisher.internal.TestUtilImpl;
import org.junit.Before;
import org.junit.Test;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;

public class UtilsTest {
    @Before
    public void setUp() {
        Util.setJenkinsUtil(new TestUtilImpl());
        Util.setAndroidUtil(new TestUtilImpl());
    }

    @Test
    public void buildRelease_basicInputs() {
        List<Integer> versionCodes = Arrays.asList(1, 2, 3);
        double fraction = 0.05;
        TrackRelease track = Util.buildRelease(versionCodes, fraction, null);

        assertThat(track.getVersionCodes(), contains(1L, 2L, 3L));
        assertEquals(0.05, track.getUserFraction(), 0.001);
        assertEquals("inProgress", track.getStatus());
        assertNull(track.getReleaseNotes());
    }

    @Test
    public void buildRelease_withInvalidFraction_releaseIsComplete() {
        List<Integer> versionCodes = Arrays.asList(1, 2, 3);
        double fraction = 0.0;
        TrackRelease track = Util.buildRelease(versionCodes, fraction, null);

        assertNull(track.getUserFraction());
        assertEquals("completed", track.getStatus());
    }

    @Test
    public void releaseNotes_nullToNull() {
        // null -> null
        assertNull(Util.transformReleaseNotes(null));

        // Any null values in the array become null values in the list
        ApkPublisher.RecentChanges[] input = new ApkPublisher.RecentChanges[]{null};
        List<LocalizedText> result = Util.transformReleaseNotes(input);
        assertThat(result, hasSize(1));
        assertNull(result.get(0));
    }

    @Test
    public void releaseNotes_transformed() {
        ApkPublisher.RecentChanges[] input = new ApkPublisher.RecentChanges[]{
                new ApkPublisher.RecentChanges("en", "The text")
        };
        List<LocalizedText> result = Util.transformReleaseNotes(input);

        assertThat(result, hasSize(1));
        assertEquals("en", result.get(0).getLanguage());
        assertEquals("The text", result.get(0).getText());
    }

    @Test
    public void bundleReleaseNotes_nullToNull() {
        // null -> null
        assertNull(Util.transformBundleReleaseNotes(null));

        // Any null values in the array become null values in the list
        AabPublisher.RecentChanges[] input = new AabPublisher.RecentChanges[]{null};
        List<LocalizedText> result = Util.transformBundleReleaseNotes(input);
        assertThat(result, hasSize(1));
        assertNull(result.get(0));
    }

    @Test
    public void bundleReleaseNotes_transformed() {
        AabPublisher.RecentChanges[] input = new AabPublisher.RecentChanges[]{
                new AabPublisher.RecentChanges("en", "The text")
        };
        List<LocalizedText> result = Util.transformBundleReleaseNotes(input);

        assertThat(result, hasSize(1));
        assertEquals("en", result.get(0).getLanguage());
        assertEquals("The text", result.get(0).getText());
    }

    @Test
    public void errorMessage_withCredentialsError_passesThrough() {
        UploadException err = new CredentialsException("This is the auth error");
        assertEquals("This is the auth error", Util.getPublisherErrorMessage(err));
    }

    @Test
    public void errorMessage_withPlainIoError_isUnknown() {
        UploadException err = new PublisherApiException(new IOException("root cause"));
        assertEquals("Unknown error: java.io.IOException: root cause", Util.getPublisherErrorMessage(err));
    }

    @Test
    public void errorMessage_withUnauthorizedErrorCode_isApiCredentialsError() {
        HttpResponseException.Builder builder =
                new HttpResponseException.Builder(401, "", new HttpHeaders());
        GoogleJsonResponseException googleException = new GoogleJsonResponseException(builder, null);
        UploadException err = new PublisherApiException(googleException);

        assertEquals("\n- The API credentials provided do not have permission to apply these changes\n",
                Util.getPublisherErrorMessage(err));
    }

    @Test
    public void errorMessage_withOtherError_fullStackTrace() {
        UploadException err = new UploadException(new GeneralSecurityException("General error"));

        String result = Util.getPublisherErrorMessage(err);
        assertThat(result, startsWith(err.toString()));
        assertThat(result,
                containsString("Caused by: java.security.GeneralSecurityException: General error"));
    }
}
