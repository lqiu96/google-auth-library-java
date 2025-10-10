package com.google.auth.oauth2;

import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

// One area of concern is regarding refreshing credentials when there are in-flight requests
// Do we need to enforce or document that both credentials should have a window where they're both active
// so that swapping won't break anything?
public class RefreshingGoogleCredentials extends OAuth2Credentials {

    private GoogleCredentials delegate;
    private final DefaultCredentialsProvider defaultCredentialsProvider = new DefaultCredentialsProvider();
    private final Object lock = new Object();

    // Expect that user/ service initializing RefreshingGoogleCredentials takes care of
    // lifecycle of the ScheduledExecutorService
    public RefreshingGoogleCredentials(ScheduledExecutorService executorService, long refreshTime, TimeUnit unit) throws IOException {
        this.delegate = defaultCredentialsProvider.getDefaultCredentialsUncached();
        executorService.schedule(() -> {
            try {
                refreshADC();
            } catch (IOException e) {
                // Option: Opt to no-op on refresh failure. This will use the existing GoogleCredential and won't break
                // user code? Log a warning so that this doesn't silently fail?
            }
        }, refreshTime, unit);
    }

    // For gRPC: GoogleAuthCallCredentials (subclass of CallCredentials) is created
    // 1. In the channel: https://github.com/googleapis/sdk-platform-java/blob/4c5a1c417a7033deb82039239728309b35e3e70b/gax-java/gax-grpc/src/main/java/com/google/api/gax/grpc/InstantiatingGrpcChannelProvider.java#L69
    // 2. In the CallContext: https://github.com/googleapis/sdk-platform-java/blob/4c5a1c417a7033deb82039239728309b35e3e70b/gax-java/gax-grpc/src/main/java/com/google/api/gax/grpc/GrpcCallContext.java#L61
    // `getRequestMetadata()` is invoked to attach the headers: https://github.com/grpc/grpc-java/blob/349a35a9b121f744a47caa9c6be293e2f33ade33/auth/src/main/java/io/grpc/auth/GoogleAuthLibraryCallCredentials.java#L118
    // For HttpJson: Credential is wrapped in HttpCredentialAdapter (https://github.com/googleapis/sdk-platform-java/blob/4c5a1c417a7033deb82039239728309b35e3e70b/gax-java/gax-httpjson/src/main/java/com/google/api/gax/httpjson/HttpRequestRunnable.java#L161)
    // This HttpCredentialAdapter invoked `getRequestMetadata()` to attach the headers: https://github.com/googleapis/google-auth-library-java/blob/c3d9ee09df30a26586b0e834cfda7763fd7854f5/oauth2_http/java/com/google/auth/http/HttpCredentialsAdapter.java#L98
    //
    // If the user passes a new RefreshingGoogleCredentials via FixedCredentialProvider, we can pass this same
    // credential to the channel and to the callcontext
    @Override
    public Map<String, List<String>> getRequestMetadata(URI uri) throws IOException {
        return delegate.getRequestMetadata(uri);
    }

    // One possible area of concern is where hasRequestMetadata() is called to see if the user
    // needs to invoke hasRequestMetadataOnly(). hasRequestMetadata() could return a result,
    // credential could refresh to a new type, and it is out of sync with the result.
    // One option is that we could limit this so this only accepts SA keys and no other type...
    @Override
    public boolean hasRequestMetadata() {
        return delegate.hasRequestMetadata();
    }

    @Override
    public boolean hasRequestMetadataOnly() {
        return delegate.hasRequestMetadataOnly();
    }

    @Override
    public void refresh() throws IOException {
        delegate.refresh();
    }

    void refreshADC() throws IOException {
        // Since this is uncached, we invoke this without retrieving cached result
        // Ideally, runs on a background thread so it doesn't block any outbound network requests
        GoogleCredentials newCredential = defaultCredentialsProvider.getDefaultCredentialsUncached();
        // Only lock when assigning the new GoogleCredential
        synchronized (lock) {
            this.delegate = newCredential;
        }
    }
}
