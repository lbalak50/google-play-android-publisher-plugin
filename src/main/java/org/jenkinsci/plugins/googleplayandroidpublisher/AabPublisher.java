package org.jenkinsci.plugins.googleplayandroidpublisher;

import com.google.jenkins.plugins.credentials.oauth.GoogleRobotCredentials;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.AbortException;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.*;
import hudson.tasks.Publisher;
import hudson.util.ComboBoxModel;
import hudson.util.FormValidation;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.export.Exported;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.io.PrintStream;
import java.io.Serializable;
import java.util.*;

import static hudson.Util.fixEmptyAndTrim;
import static hudson.Util.tryParseNumber;
import static org.jenkinsci.plugins.googleplayandroidpublisher.Constants.PERCENTAGE_FORMATTER;
import static org.jenkinsci.plugins.googleplayandroidpublisher.ReleaseTrack.fromConfigValue;
import static org.jenkinsci.plugins.googleplayandroidpublisher.Util.*;

/**
 * Uploads Android application files to the Google Play Developer Console.
 */
public class AabPublisher extends GooglePlayPublisher {

    @DataBoundSetter
    private String aabFilesPattern;

    @DataBoundSetter
    private String applicationId;

    @DataBoundSetter
    private String deobfuscationFilesPattern;

    @DataBoundSetter
    private String trackName;

    @DataBoundSetter
    private String rolloutPercentage;

    @DataBoundSetter
    private RecentChanges[] recentChangeList;

    @DataBoundConstructor
    public AabPublisher() {
    }

    public String getAabFilesPattern() {
        return fixEmptyAndTrim(aabFilesPattern);
    }

    public String getApplicationId() {
        return fixEmptyAndTrim(applicationId);
    }

    private String getExpandedApplicationId() throws IOException, InterruptedException {
        return expand(getApplicationId());
    }

    private String getExpandedAabFilesPattern() throws IOException, InterruptedException {
        return expand(getAabFilesPattern());
    }

    public String getDeobfuscationFilesPattern() {
        return fixEmptyAndTrim(deobfuscationFilesPattern);
    }

    private String getExpandedDeobfuscationFilesPattern() throws IOException, InterruptedException {
        return expand(getDeobfuscationFilesPattern());
    }

    public String getTrackName() {
        return fixEmptyAndTrim(trackName);
    }

    private String getCanonicalTrackName() throws IOException, InterruptedException {
        String name = expand(getTrackName());
        if (name == null) {
            return null;
        }
        return name.toLowerCase(Locale.ENGLISH);
    }

    public String getRolloutPercentage() {
        return fixEmptyAndTrim(rolloutPercentage);
    }

    @SuppressFBWarnings("NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE")
    private double getRolloutPercentageValue() throws IOException, InterruptedException {
        String pct = getRolloutPercentage();
        if (pct != null) {
            // Allow % characters in the config
            pct = pct.replace("%", "");
        }
        // If no valid numeric value was set, we will roll out to 100%
        return tryParseNumber(expand(pct), 100).doubleValue();
    }

    @SuppressFBWarnings("EI_EXPOSE_REP")
    public RecentChanges[] getRecentChangeList() {
        return recentChangeList;
    }

    private RecentChanges[] getExpandedRecentChangesList() throws IOException, InterruptedException {
        if (recentChangeList == null) {
            return null;
        }
        RecentChanges[] expanded = new RecentChanges[recentChangeList.length];
        for (int i = 0; i < recentChangeList.length; i++) {
            RecentChanges r = recentChangeList[i];
            expanded[i] = new RecentChanges(expand(r.language), expand(r.text));
        }
        return expanded;
    }

    private boolean isConfigValid(PrintStream logger) throws IOException, InterruptedException {
        final List<String> errors = new ArrayList<>();

        // Check whether a file pattern was provided
        if (getExpandedAabFilesPattern() == null) {
            errors.add("Path or pattern to AAB file was not specified");
        }

        // Track name is also required
        final String trackName = getCanonicalTrackName();
        final ReleaseTrack track = fromConfigValue(trackName);
        if (trackName == null) {
            errors.add("Release track was not specified");
        } else if (track == null) {
            errors.add(String.format("'%s' is not a valid release track", trackName));
        } else {
            // Check for valid rollout percentage
            double pct = getRolloutPercentageValue();
            if (Double.compare(pct, 0) < 0 || Double.compare(pct, 100) > 0) {
                errors.add(String.format("%s%% is not a valid rollout percentage", PERCENTAGE_FORMATTER.format(pct)));
            }
        }

        // Print accumulated errors
        if (!errors.isEmpty()) {
            logger.println("Cannot upload to Google Play:");
            for (String error : errors) {
                logger.print("- ");
                logger.println(error);
            }
        }

        return errors.isEmpty();
    }

    @Override
    public void perform(@Nonnull Run<?, ?> run, @Nonnull FilePath workspace, @Nonnull Launcher launcher,
                        @Nonnull TaskListener listener) throws InterruptedException, IOException {
        super.perform(run, workspace, launcher, listener);

        // Calling publishApk logs the reason when a failure occurs, so in that case we just need to throw here
        if (!publishApk(run, workspace, listener)) {
            throw new AbortException("APK upload failed");
        }
    }

    private boolean publishApk(@Nonnull Run<?, ?> run, @Nonnull FilePath workspace, @Nonnull TaskListener listener)
            throws InterruptedException, IOException {
        final PrintStream logger = listener.getLogger();

        // Check whether we should execute at all
        final Result buildResult = run.getResult();
        if (buildResult != null && buildResult.isWorseThan(Result.UNSTABLE)) {
            logger.println("Skipping upload to Google Play due to build result");
            return true;
        }

        // Check that the job has been configured correctly
        if (!isConfigValid(logger)) {
            return false;
        }

        // For the future of AAB
        final String filesPattern = getExpandedAabFilesPattern();

        List<String> relativePaths = workspace.act(new FindFilesTask(filesPattern));
        if (relativePaths.isEmpty()) {
            logger.println(String.format("No AAB files matching the pattern '%s' could be found", filesPattern));
            return false;
        }

        final List<FilePath> aabFiles = new ArrayList<>();
        for (String path : relativePaths) {
            FilePath aab = workspace.child(path);
            aabFiles.add(aab);
        }

        // Find the obfuscation mapping filename(s) which match the pattern after variable expansion
        final Map<FilePath, FilePath> aabFilesToMappingFiles = new HashMap<>();
        final String mappingFilesPattern = getExpandedDeobfuscationFilesPattern();
        if (getExpandedDeobfuscationFilesPattern() != null) {
            List<String> relativeMappingPaths = workspace.act(new FindFilesTask(mappingFilesPattern));
            if (relativeMappingPaths.isEmpty()) {
                logger.println(String.format("No obfuscation mapping files matching the pattern '%s' could be found; " +
                        "no files will be uploaded", filesPattern));
                return false;
            }

            // Create a mapping of APK files to their obfuscation mapping file
            if (relativeMappingPaths.size() == 1) {
                // If there is only one mapping file, associate it with each of the APKs
                FilePath mappingFile = workspace.child(relativeMappingPaths.get(0));
                for (FilePath aab : aabFiles) {
                    aabFilesToMappingFiles.put(aab, mappingFile);
                }
            } else if (relativeMappingPaths.size() == aabFiles.size()) {
                // If there are multiple mapping files, this usually means that there is one per dimension;
                // the folder structure will typically look like this for the APKs and their mapping files:
                //
                // - build/outputs/apk/dimension_one/release/app-release.apk
                // - build/outputs/apk/dimension_two/release/app-release.apk
                // - build/outputs/mapping/dimension_one/release/mapping.txt
                // - build/outputs/mapping/dimension_two/release/mapping.txt
                //
                // i.e. an APK and its mapping file don't share the same path prefix, but as the directories are named
                // by dimension, we assume that the order of the output of both FindFileTasks here will be the same
                //
                // We use this assumption here to associate the individual mapping files with the discovered APK files
                for (int i = 0, n = aabFiles.size(); i < n; i++) {
                    aabFilesToMappingFiles.put(aabFiles.get(i), workspace.child(relativeMappingPaths.get(i)));
                }
            } else {
                // If, for some reason, the number of APK files don't match, we won't deal with this situation
                logger.println(String.format("There are %d APKs to be uploaded, but only %d obfuscation mapping " +
                                "files were found matching the pattern '%s':",
                        aabFiles.size(), relativeMappingPaths.size(), mappingFilesPattern));
                for (String path : relativePaths) {
                    logger.println(String.format("- %s", path));
                }
                for (String path : relativeMappingPaths) {
                    logger.println(String.format("- %s", path));
                }
                return false;
            }
        }

        // Upload the file(s) from the workspace
        try {
            GoogleRobotCredentials credentials = getCredentialsHandler().getServiceAccountCredentials();
            return workspace.act(new AabUploadTask(listener, credentials, getExpandedApplicationId(), workspace, aabFiles,
                    aabFilesToMappingFiles, fromConfigValue(getCanonicalTrackName()), getRolloutPercentageValue(),
                    getExpandedRecentChangesList()));
        } catch (UploadException e) {
            logger.println(String.format("Upload failed: %s", getPublisherErrorMessage(e)));
            logger.println("- No changes have been applied to the Google Play account");
        }
        return false;
    }

    public static final class RecentChanges extends AbstractDescribableImpl<RecentChanges> implements Serializable {

        private static final long serialVersionUID = 1;

        @Exported
        public final String language;

        @Exported
        public final String text;

        @DataBoundConstructor
        public RecentChanges(String language, String text) {
            this.language = language;
            this.text = text;
        }

        @Extension
        public static class DescriptorImpl extends Descriptor<RecentChanges> {

            @Override
            public String getDisplayName() {
                return "Recent changes";
            }

            public ComboBoxModel doFillLanguageItems() {
                return new ComboBoxModel(SUPPORTED_LANGUAGES);
            }

            public FormValidation doCheckLanguage(@QueryParameter String value) {
                value = fixEmptyAndTrim(value);
                if (value != null && !value.matches(REGEX_LANGUAGE) && !value.matches(REGEX_VARIABLE)) {
                    return FormValidation.warning("Should be a language code like 'be' or 'en-GB'");
                }
                return FormValidation.ok();
            }

            public FormValidation doCheckText(@QueryParameter String value) {
                value = fixEmptyAndTrim(value);
                if (value != null && value.length() > 500) {
                    return FormValidation.error("Recent changes text must be 500 characters or fewer");
                }
                return FormValidation.ok();
            }

        }

    }

    @Symbol("androidAabUpload")
    @Extension
    public static final class DescriptorImpl extends GooglePlayBuildStepDescriptor<Publisher> {

        public String getDisplayName() {
            return "Upload Android AAB to Google Play";
        }

    }

}
