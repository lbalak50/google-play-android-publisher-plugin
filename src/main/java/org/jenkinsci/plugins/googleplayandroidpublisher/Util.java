package org.jenkinsci.plugins.googleplayandroidpublisher;

import com.google.api.services.androidpublisher.AndroidPublisher;
import com.google.api.services.androidpublisher.model.LocalizedText;
import com.google.api.services.androidpublisher.model.TrackRelease;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Throwables;
import com.google.jenkins.plugins.credentials.oauth.GoogleRobotCredentials;
import hudson.FilePath;
import hudson.model.AbstractBuild;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.remoting.VirtualChannel;
import java.util.Objects;
import jenkins.MasterToSlaveFileCallable;
import net.dongliu.apk.parser.bean.ApkMeta;
import org.jenkinsci.plugins.googleplayandroidpublisher.internal.AndroidUtil;
import org.jenkinsci.plugins.googleplayandroidpublisher.internal.JenkinsUtil;
import org.jenkinsci.plugins.googleplayandroidpublisher.internal.UtilsImpl;
import org.jenkinsci.plugins.tokenmacro.MacroEvaluationException;
import org.jenkinsci.plugins.tokenmacro.TokenMacro;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import javax.annotation.Nullable;

import static hudson.Util.fixEmptyAndTrim;

public class Util {
    private static JenkinsUtil sJenkins = UtilsImpl.getInstance();
    private static AndroidUtil sAndroid = UtilsImpl.getInstance();

    /** Regex for the BCP 47 language codes used by Google Play. */
    static final String REGEX_LANGUAGE = "[a-z]{2,3}([-_][0-9A-Z]{2,})?";

    // From hudson.Util.VARIABLE
    static final String REGEX_VARIABLE = "\\$([A-Za-z0-9_]+|\\{[A-Za-z0-9_]+\\}|\\$)";

    /** A (potentially non-exhaustive) list of languages supported by Google Play for app description text etc.. */
    static final String[] SUPPORTED_LANGUAGES =
            { "af", "am", "ar", "be", "bg", "ca", "cs-CZ", "da-DK", "de-DE", "el-GR", "en-GB", "en-US", "es-419",
                    "es-ES", "es-US", "et", "fa", "fi-FI", "fil", "fr-CA", "fr-FR", "hi-IN", "hr", "hu-HU", "id",
                    "it-IT", "iw-IL", "ja-JP", "ko-KR", "lt", "lv", "ms", "nl-NL", "no-NO", "pl-PL", "pt-BR", "pt-PT",
                    "rm", "ro", "ru-RU", "sk", "sl", "sr", "sv-SE", "sw", "th", "tr-TR", "uk", "vi", "zh-CN", "zh-TW",
                    "zu" };

    /** @return The version of this Jenkins plugin, e.g. "1.0" or "1.1-SNAPSHOT" (for dev releases). */
    public static String getPluginVersion() {
        return sJenkins.getPluginVersion();
    }

    /** @return The application ID of the given APK file. */
    public static String getApplicationId(FilePath apk) throws IOException, InterruptedException {
        return apk.act(new MasterToSlaveFileCallable<String>() {
            @Override
            public String invoke(File f, VirtualChannel channel) throws IOException {
                return sAndroid.getApkPackageName(f);
            }
        });
    }

    /** @return The version code of the given APK file. */
    static int getVersionCode(FilePath apk) throws IOException, InterruptedException {
        return apk.act(new MasterToSlaveFileCallable<Integer>() {
            @Override
            public Integer invoke(File f, VirtualChannel channel) throws IOException {
                return sAndroid.getApkVersionCode(f);
            }
        });
    }

    /** @return The application metadata of the given APK file. */
    static ApkMeta getApkMetadata(File apk) throws IOException {
        return sAndroid.getApkMetadata(apk);
    }

    /** @return The given value with variables expanded and trimmed; {@code null} if that results in an empty string. */
    static String expand(Run<?, ?> run, TaskListener listener, String value)
            throws InterruptedException, IOException {
        // If this is a pipeline run, there's no need to expand tokens
        if (!(run instanceof AbstractBuild)) {
            return value;
        }

        try {
            final AbstractBuild build = (AbstractBuild) run;
            return fixEmptyAndTrim(TokenMacro.expandAll(build, listener, value));
        } catch (MacroEvaluationException e) {
            listener.getLogger().println(e.getMessage());
            return value;
        }
    }

    /** @return A user-friendly(ish) Google Play API error message, if one could be found in the given exception. */
    static String getPublisherErrorMessage(UploadException e) {
        if (e instanceof CredentialsException) {
            return e.getMessage();
        }
        if (e instanceof PublisherApiException) {
            // TODO: Here we could map error reasons like "apkUpgradeVersionConflict" to better (and localised) text
            List<String> errors = ((PublisherApiException) e).getErrorMessages();
            if (errors == null || errors.isEmpty()) {
                return "Unknown error: " + e.getCause();
            }
            StringBuilder message = new StringBuilder("\n");
            for (String error : errors) {
                message.append("- ");
                message.append(error);
                message.append('\n');
            }
            return message.toString();
        }

        // Otherwise print the whole stacktrace, as it's something unrelated to this plugin
        return Throwables.getStackTraceAsString(e);
    }

    /**
     * @return An Android Publisher client, using the configured credentials.
     * @throws GeneralSecurityException If reading the service account credentials failed.
     */
    static AndroidPublisher getPublisherClient(GoogleRobotCredentials credentials, String pluginVersion)
            throws GeneralSecurityException {
        return sJenkins.createPublisherClient(credentials, pluginVersion);
    }

    @Nullable
    static List<LocalizedText> transformReleaseNotes(@Nullable ApkPublisher.RecentChanges[] list) {
        if (list != null) {
            return Arrays.stream(list).map(it -> {
                if (it == null) return null;
                return new LocalizedText()
                        .setLanguage(it.language)
                        .setText(it.text);
            }).collect(Collectors.toList());
        }
        return null;
    }

    @Nullable
    static List<LocalizedText> transformBundleReleaseNotes(@Nullable AabPublisher.RecentChanges[] list) {
        if (list != null) {
            return Arrays.stream(list).map(it -> {
                if (it == null) return null;
                return new LocalizedText()
                        .setLanguage(it.language)
                        .setText(it.text);
            }).collect(Collectors.toList());
        }
        return null;
    }

    static TrackRelease buildRelease(List<Integer> versionCodes, double userFraction, @Nullable List<LocalizedText> releaseNotes) {
        List<Long> longVersionCodes = versionCodes.stream().map(integer -> {
            if (integer == null) return null;
            return integer.longValue();
        }).collect(Collectors.toList());

        // We need to explicitly set the fraction to null if it's not 0 < x < 1.
        // If so, then we also mark the rollout as done, rather than in-progress:
        // https://developers.google.com/android-publisher/api-ref/edits/tracks#resource
        boolean hasValidFraction = (Double.compare(userFraction, 0) != 0) && (Double.compare(userFraction, 1) != 0);
        Double fraction = hasValidFraction ? userFraction : null;
        String status = hasValidFraction ? "inProgress" : "completed";

        TrackRelease release = new TrackRelease()
                .setVersionCodes(longVersionCodes)
                .setUserFraction(fraction)
                .setStatus(status);

        if (releaseNotes != null) release.setReleaseNotes(releaseNotes);
        return release;
    }

    @VisibleForTesting
    public static void setJenkinsUtil(JenkinsUtil util) {
        sJenkins = Objects.requireNonNull(util);
    }

    @VisibleForTesting
    public static void setAndroidUtil(AndroidUtil util) {
        sAndroid = Objects.requireNonNull(util);
    }
}
