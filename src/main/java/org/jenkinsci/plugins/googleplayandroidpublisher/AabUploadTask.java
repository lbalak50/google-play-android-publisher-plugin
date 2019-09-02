package org.jenkinsci.plugins.googleplayandroidpublisher;

import com.google.api.client.http.FileContent;
import com.google.api.services.androidpublisher.model.Apk;
import com.google.api.services.androidpublisher.model.Bundle;
import com.google.api.services.androidpublisher.model.LocalizedText;
import com.google.api.services.androidpublisher.model.TrackRelease;
import com.google.jenkins.plugins.credentials.oauth.GoogleRobotCredentials;
import hudson.FilePath;
import hudson.model.TaskListener;
import org.apache.commons.codec.digest.DigestUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.*;

import static org.jenkinsci.plugins.googleplayandroidpublisher.AabPublisher.RecentChanges;
import static org.jenkinsci.plugins.googleplayandroidpublisher.Constants.DEOBFUSCATION_FILE_TYPE_PROGUARD;

class AabUploadTask extends TrackPublisherTask<Boolean> {

    private final FilePath workspace;
    private final List<FilePath> aabFiles;
    private final Map<FilePath, FilePath> apkFilesToMappingFiles;
    private final RecentChanges[] recentChangeList;

    AabUploadTask(TaskListener listener, GoogleRobotCredentials credentials, String applicationId,
                  FilePath workspace, List<FilePath> aabFiles, Map<FilePath, FilePath> apkFilesToMappingFiles,
                  ReleaseTrack track, double rolloutPercentage, RecentChanges[] recentChangeList) {
        super(listener, credentials, applicationId, track, rolloutPercentage);
        this.workspace = workspace;
        this.aabFiles = aabFiles;
        this.apkFilesToMappingFiles = apkFilesToMappingFiles;
        this.recentChangeList = recentChangeList;
    }

    protected Boolean execute() throws IOException, InterruptedException {
        // Open an edit via the Google Play API, thereby ensuring that our credentials etc. are working
        logger.println(String.format("Authenticating to Google Play API...%n" +
                "- Credential:     %s%n" +
                "- Application ID: %s%n", getCredentialName(), applicationId));
        createEdit(applicationId);

        // Upload each of the APKs
        logger.println(String.format("Uploading %d AAB(s) with application ID: %s%n", aabFiles.size(), applicationId));
        final ArrayList<Integer> uploadedVersionCodes = new ArrayList<>();
        for (FilePath aabFile : aabFiles) {

//            final ApkMeta metadata = getApkMetadata(new File(aabFile.getRemote()));
//            final String apkSha1Hash = getSha1Hash(aabFile.getRemote());

            // Log some useful information about the file that will be uploaded
//            logger.println(String.format("      APK file: %s", getRelativeFileName(aabFile)));
//            logger.println(String.format("    SHA-1 hash: %s", apkSha1Hash));
//            logger.println(String.format("   versionCode: %d", metadata.getVersionCode()));
//            logger.println(String.format(" minSdkVersion: %s", metadata.getMinSdkVersion()));

            // Check whether this APK already exists on the server (i.e. uploading it would fail)
//            for (Apk apk : existingApks) {
//                if (apk.getBinary().getSha1().toLowerCase(Locale.ENGLISH).equals(apkSha1Hash)) {
//                    logger.println();
//                    logger.println("This APK already exists in the Google Play account; it cannot be uploaded again");
//                    return false;
//                }
//            }

            // If not, we can upload the file
            logger.println(String.format("About to start uploading AAB %s", aabFile.getRemote()));
            FileContent apk =
                    new FileContent("application/octet-stream", new File(aabFile.getRemote()));
            Bundle uploadedAab = editService.bundles().upload(applicationId, editId, apk).execute();
            uploadedVersionCodes.add(uploadedAab.getVersionCode());

            final String apkSha1Hash = getSha1Hash(aabFile.getRemote());

            // Log some useful information about the file that will be uploaded
            logger.println(String.format("      AAB file: %s", getRelativeFileName(aabFile)));
            logger.println(String.format("    SHA-1 hash: %s", apkSha1Hash));
            logger.println(String.format("   versionCode: %d", uploadedAab.getVersionCode()));

            // Upload the ProGuard mapping file for this APK, if there is one
            final FilePath mappingFile = apkFilesToMappingFiles.get(aabFile);
            if (mappingFile != null) {
                final String relativeFileName = getRelativeFileName(mappingFile);

                // Google Play API doesn't accept empty mapping files
                logger.println(String.format(" Mapping file size: %s", mappingFile.length()));
                if (mappingFile.length() == 0) {
                    logger.println(String.format(" Ignoring empty ProGuard mapping file: %s", relativeFileName));
                } else {
                    logger.println(String.format(" Uploading associated ProGuard mapping file: %s", relativeFileName));
                    FileContent mapping =
                            new FileContent("application/octet-stream", new File(mappingFile.getRemote()));
                    editService.deobfuscationfiles().upload(applicationId, editId, uploadedAab.getVersionCode(),
                            DEOBFUSCATION_FILE_TYPE_PROGUARD, mapping).execute();
                }
            }
            logger.println("");
        }

        // Assign all uploaded APKs to the configured track
        List<LocalizedText> releaseNotes = Util.transformBundleReleaseNotes(recentChangeList);
        TrackRelease release = Util.buildRelease(uploadedVersionCodes, rolloutFraction, releaseNotes);
        assignApksToTrack(track, rolloutFraction, release);

        // Commit all the changes
        try {
            logger.println("Applying changes to Google Play...");
            editService.commit(applicationId, editId).execute();
        } catch (SocketTimeoutException e) {
            // The API is quite prone to timing out for no apparent reason,
            // despite having successfully committed the changes on the backend.
            // So here we check whether the APKs uploaded were actually committed
            logger.println(String.format("- An error occurred while applying changes: %s", e));
            logger.println("- Checking whether the changes have been applied anyway...\n");
            if (!wereApksUploaded(uploadedVersionCodes)) {
                logger.println("The APKs that were uploaded were not found on Google Play");
                logger.println("- No changes have been applied to the Google Play account");
                return false;
            }
        }

        // If committing didn't throw an exception, everything worked fine
        logger.println("Changes were successfully applied to Google Play");
        return true;
    }

    /**
     * Starts a new API session and determines whether a list of version codes were successfully uploaded.
     *
     * @param uploadedVersionCodes The list to be checked for existence.
     * @return {@code true} if APK version codes in the list were found to now exist on Google Play.
     */
    private boolean wereApksUploaded(Collection<Integer> uploadedVersionCodes) throws IOException {
        // Last edit is finished; create a new one to get the current state
        createEdit(applicationId);

        // Get the current list of version codes
        List<Integer> currentVersionCodes = new ArrayList<>();
        List<Apk> currentApks = editService.apks().list(applicationId, editId).execute().getApks();
        if (currentApks == null) currentApks = Collections.emptyList();
        for (Apk apk : currentApks) {
            currentVersionCodes.add(apk.getVersionCode());
        }

        // The upload succeeded if the current list of version codes intersects with the list we tried to upload
        return uploadedVersionCodes.removeAll(currentVersionCodes);
    }

    /**
     * @return The path to the given file, relative to the build workspace.
     */
    private String getRelativeFileName(FilePath file) {
        final String ws = workspace.getRemote();
        String path = file.getRemote();
        if (path.startsWith(ws) && path.length() > ws.length()) {
            path = path.substring(ws.length());
        }
        if (path.charAt(0) == File.separatorChar && path.length() > 1) {
            path = path.substring(1);
        }
        return path;
    }

    /**
     * @return The SHA-1 hash of the given file, as a lower-case hex string.
     */
    private static String getSha1Hash(String path) throws IOException {
        FileInputStream fis = new FileInputStream(path);
        try {
            return DigestUtils.sha1Hex(fis).toLowerCase(Locale.ENGLISH);
        } finally {
            fis.close();
        }
    }
}
