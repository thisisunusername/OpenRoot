// SPDX-License-Identifier: GPL-3.0-or-later OR Apache-2.0

package com.hexo141.liquidglass.adb;

import android.content.Context;
import android.os.Build;

import androidx.annotation.CallSuper;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import androidx.annotation.WorkerThread;

import java.io.Closeable;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import javax.security.auth.DestroyFailedException;

import com.hexo141.liquidglass.adb.mdns.AdbMdns;

@SuppressWarnings("unused")
public abstract class AbsAdbConnectionManager implements Closeable {
    private final Object mLock = new Object();
    @Nullable
    private AdbConnection mAdbConnection;
    private String mHostAddress = "127.0.0.1";
    private int mApi = Build.VERSION_CODES.BASE;
    private long mTimeout = Long.MAX_VALUE;
    private TimeUnit mTimeoutUnit = TimeUnit.MILLISECONDS;
    private boolean mThrowOnUnauthorised = false;

    /**
     * When set, every {@code shell:} request is served by this delegate instead of {@link AdbConnection}.
     *
     * This is how the app runs on devices without wireless debugging: {@code ShizukuShell} starts a
     * local process with shell privilege, and no ADB daemon, mDNS or pairing code is involved.
     * Keeping the hook here (rather than in every payload runner) means the runners stay
     * transport-neutral.
     */
    @Nullable
    private volatile ShellProvider mLocalShell;

    /** A transport that hands out shell channels without an ADB connection. */
    public interface ShellProvider {
        /** @param destination an ADB service name, e.g. {@code shell:ls -l} or {@code shell,pty:...} */
        @NonNull
        ShellStream openShellStream(@NonNull String destination) throws IOException;
    }

    /** Switches this manager to a non-ADB transport, e.g. Shizuku. Pass {@code null} to go back. */
    public void setLocalShell(@Nullable ShellProvider provider) {
        mLocalShell = provider;
        if (provider != null) {
            mHostAddress = "local";
        }
    }

    /** @return the delegate set by {@link #setLocalShell(ShellProvider)}, or {@code null} for ADB. */
    @Nullable
    public ShellProvider getLocalShell() {
        return mLocalShell;
    }

    /**
     * Return generated/stored private key.
     */
    @NonNull
    protected abstract PrivateKey getPrivateKey();

    /**
     * Return public key wrapped around a certificate.
     */
    @NonNull
    protected abstract Certificate getCertificate();

    /**
     * Return a name for the device. This can be the app label, hostname or user@hostname.
     */
    @NonNull
    protected abstract String getDeviceName();

    /**
     * Set host address for this connection. On the same device, this should be {@code 127.0.0.1}.
     */
    @CallSuper
    public void setHostAddress(@NonNull String hostAddress) {
        mHostAddress = Objects.requireNonNull(hostAddress);
    }

    /**
     * Get host address for this connection. Default value is {@code 127.0.0.1}.
     */
    @NonNull
    public String getHostAddress() {
        return mHostAddress;
    }

    /**
     * Set Android API (i.e. SDK) version for this connection. If the daemon and the client are located in the same
     * directory, the value should be {@link Build.VERSION#SDK_INT} in order to improve performance as well as security.
     *
     * @param api The API version, default is {@link Build.VERSION_CODES#BASE}.
     */
    public void setApi(int api) {
        this.mApi = api;
    }

    /**
     * Get Android API (i.e. SDK) version for this connection. Default value is {@link Build.VERSION_CODES#BASE}.
     */
    public int getApi() {
        return mApi;
    }

    /**
     * Set time to wait for the connection to be made.
     *
     * @param timeout Timeout value
     * @param unit    Timeout unit
     */
    @CallSuper
    public void setTimeout(long timeout, TimeUnit unit) {
        mTimeout = timeout;
        mTimeoutUnit = unit;
    }

    /**
     * Get time to wait for the connection to be made. If not set using {@link #setTimeout(long, TimeUnit)}, the default
     * timeout is {@link Long#MAX_VALUE} milliseconds.
     *
     * @return Timeout in milliseconds
     */
    public long getTimeout() {
        return mTimeoutUnit.toMillis(mTimeout);
    }

    /**
     * Get the unit for the timeout. If not set using {@link #setTimeout(long, TimeUnit)}, the default timeout unit is
     * {@link TimeUnit#MILLISECONDS}.
     */
    @NonNull
    public TimeUnit getTimeoutUnit() {
        return mTimeoutUnit;
    }

    /**
     * Set whether to throw {@link AdbAuthenticationFailedException} if the daemon rejects the first authentication
     * attempt.
     *
     * @param throwOnUnauthorised {@code true} to throw {@link AdbAuthenticationFailedException} or {@code false}
     *                            otherwise.
     */
    @CallSuper
    public void setThrowOnUnauthorised(boolean throwOnUnauthorised) {
        mThrowOnUnauthorised = throwOnUnauthorised;
    }

    /**
     * Get whether to throw {@link AdbAuthenticationFailedException} if the daemon rejects the first authentication
     * attempt.
     *
     * @return {@code true} if the system is configured to throw {@link AdbAuthenticationFailedException} or
     * {@code false} otherwise. The default value is {@code false}.
     */
    public boolean isThrowOnUnauthorised() {
        return mThrowOnUnauthorised;
    }

    /**
     * Get the {@link AdbConnection} backed by this object.
     *
     * @return Underlying {@link AdbConnection}, or {@code null} if the connection hasn't been made yet.
     */
    @CallSuper
    @Nullable
    public AdbConnection getAdbConnection() {
        synchronized (mLock) {
            return mAdbConnection;
        }
    }

    /**
     * Check if a shell channel can be opened: either an ADB daemon is connected, or a local
     * transport such as Shizuku took over.
     *
     * @return {@code true} if connected, {@code false} otherwise.
     */
    public boolean isConnected() {
        if (mLocalShell != null) return true;
        synchronized (mLock) {
            return mAdbConnection != null && mAdbConnection.isConnected() && mAdbConnection.isConnectionEstablished();
        }
    }

    /**
     * Attempt to connect to ADB by performing an automatic network discovery of TLS host and port. Host address set by
     * {@link #setHostAddress(String)} is ignored.
     *
     * @param context       Application context
     * @param timeoutMillis Amount of time spent in searching for a host and a port.
     * @return {@code true} if and only if the connection is successful. It returns {@code false} if the connection
     * attempt is unsuccessful, or it has already been made.
     * @throws IOException                      If the socket connection could not be made.
     * @throws InterruptedException             If timeout has reached.
     * @throws AdbAuthenticationFailedException If {@link #isThrowOnUnauthorised()} is set to {@code true}, and the ADB
     *                                          daemon has rejected the first authentication attempt, which indicates
     *                                          that the daemon has not saved the public key from a previous connection.
     * @throws AdbPairingRequiredException      If ADB lacks pairing
     */
    @WorkerThread
    @RequiresApi(Build.VERSION_CODES.JELLY_BEAN)
    public boolean connectTls(@NonNull Context context, long timeoutMillis)
            throws IOException, InterruptedException, AdbPairingRequiredException {
        return autoConnect(context, AdbMdns.SERVICE_TYPE_TLS_CONNECT, timeoutMillis);
    }

    /**
     * Attempt to connect to ADB by performing an automatic network discovery of TCP host and port. Host address set by
     * {@link #setHostAddress(String)} is ignored.
     *
     * @param context       Application context
     * @param timeoutMillis Amount of time spent in searching for a host and a port.
     * @return {@code true} if and only if the connection is successful. It returns {@code false} if the connection
     * attempt is unsuccessful, or it has already been made.
     * @throws IOException                      If the socket connection could not be made.
     * @throws InterruptedException             If timeout has reached.
     * @throws AdbAuthenticationFailedException If {@link #isThrowOnUnauthorised()} is set to {@code true}, and the ADB
     *                                          daemon has rejected the first authentication attempt, which indicates
     *                                          that the daemon has not saved the public key from a previous connection.
     * @throws AdbPairingRequiredException      If ADB lacks pairing
     */
    @WorkerThread
    @RequiresApi(Build.VERSION_CODES.JELLY_BEAN)
    public boolean connectTcp(@NonNull Context context, long timeoutMillis)
            throws IOException, InterruptedException, AdbPairingRequiredException {
        return autoConnect(context, AdbMdns.SERVICE_TYPE_ADB, timeoutMillis);
    }

    /**
     * Attempt to connect to ADB by performing an automatic network discovery of host and port. Host address set by
     * {@link #setHostAddress(String)} is ignored.
     *
     * @param context       Application context
     * @param timeoutMillis Amount of time spent in searching for a host and a port.
     * @return {@code true} if and only if the connection is successful. It returns {@code false} if the connection
     * attempt is unsuccessful, or it has already been made.
     * @throws IOException                      If the socket connection could not be made.
     * @throws InterruptedException             If timeout has reached.
     * @throws AdbAuthenticationFailedException If {@link #isThrowOnUnauthorised()} is set to {@code true}, and the ADB
     *                                          daemon has rejected the first authentication attempt, which indicates
     *                                          that the daemon has not saved the public key from a previous connection.
     * @throws AdbPairingRequiredException      If ADB lacks pairing
     */
    @WorkerThread
    @RequiresApi(Build.VERSION_CODES.JELLY_BEAN)
    public boolean autoConnect(@NonNull Context context, long timeoutMillis)
            throws IOException, InterruptedException, AdbPairingRequiredException {
        synchronized (mLock) {
            AtomicInteger atomicPort = new AtomicInteger(-1);
            AtomicReference<String> atomicHostAddress = new AtomicReference<>(null);
            CountDownLatch resolveHostAndPort = new CountDownLatch(1);

            AdbMdns adbMdnsTcp = new AdbMdns(context, AdbMdns.SERVICE_TYPE_ADB, (hostAddress, port) -> {
                if (hostAddress != null) {
                    atomicHostAddress.set(hostAddress.getHostAddress());
                    atomicPort.set(port);
                }
                resolveHostAndPort.countDown();
            });
            adbMdnsTcp.start();

            AdbMdns adbMdnsTls = new AdbMdns(context, AdbMdns.SERVICE_TYPE_TLS_CONNECT, (hostAddress, port) -> {
                if (hostAddress != null) {
                    atomicHostAddress.set(hostAddress.getHostAddress());
                    atomicPort.set(port);
                }
                resolveHostAndPort.countDown();
            });
            adbMdnsTls.start();

            try {
                if (!resolveHostAndPort.await(timeoutMillis, TimeUnit.MILLISECONDS)) {
                    throw new InterruptedException("Timed out while trying to find a valid host address and port");
                }
            } finally {
                adbMdnsTcp.stop();
                adbMdnsTls.stop();
            }

            String host = atomicHostAddress.get();
            int port = atomicPort.get();

            if (host == null || port == -1) {
                throw new IOException("Could not find any valid host address or port");
            }

            mHostAddress = host;
            mAdbConnection = new AdbConnection.Builder(host, port)
                    .setApi(mApi)
                    .setKeyPair(getAdbKeyPair())
                    .setDeviceName(Objects.requireNonNull(getDeviceName()))
                    .build();
            return mAdbConnection.connect(mTimeout, mTimeoutUnit, mThrowOnUnauthorised);
        }
    }

    @WorkerThread
    @RequiresApi(Build.VERSION_CODES.JELLY_BEAN)
    private boolean autoConnect(@NonNull Context context, @AdbMdns.ServiceType @NonNull String serviceType, long timeoutMillis)
            throws IOException, InterruptedException, AdbPairingRequiredException {
        synchronized (mLock) {
            AtomicInteger atomicPort = new AtomicInteger(-1);
            AtomicReference<String> atomicHostAddress = new AtomicReference<>(null);
            CountDownLatch resolveHostAndPort = new CountDownLatch(1);

            AdbMdns adbMdns = new AdbMdns(context, serviceType, (hostAddress, port) -> {
                if (hostAddress != null) {
                    atomicHostAddress.set(hostAddress.getHostAddress());
                    atomicPort.set(port);
                }
                resolveHostAndPort.countDown();
            });
            adbMdns.start();

            try {
                if (!resolveHostAndPort.await(timeoutMillis, TimeUnit.MILLISECONDS)) {
                    throw new InterruptedException("Timed out while trying to find a valid host address and port");
                }
            } finally {
                adbMdns.stop();
            }

            String host = atomicHostAddress.get();
            int port = atomicPort.get();

            if (host == null || port == -1) {
                throw new IOException("Could not find any valid host address or port");
            }

            mHostAddress = host;
            mAdbConnection = new AdbConnection.Builder(host, port)
                    .setApi(mApi)
                    .setKeyPair(getAdbKeyPair())
                    .setDeviceName(Objects.requireNonNull(getDeviceName()))
                    .build();
            return mAdbConnection.connect(mTimeout, mTimeoutUnit, mThrowOnUnauthorised);
        }
    }

    /**
     * Attempt to connect to ADB given a port number. Host address is set via {@link #setHostAddress(String)}.
     *
     * @param port Port number
     * @return {@code true} if and only if the connection is successful. It returns {@code false} if the connection
     * attempt is unsuccessful, or it has already been made.
     * @throws IOException                      If the socket connection could not be made.
     * @throws InterruptedException             If timeout has reached.
     * @throws AdbAuthenticationFailedException If {@link #isThrowOnUnauthorised()} is set to {@code true}, and the ADB
     *                                          daemon has rejected the first authentication attempt, which indicates
     *                                          that the daemon has not saved the public key from a previous connection.
     * @throws AdbPairingRequiredException      If ADB lacks pairing
     */
    @WorkerThread
    public boolean connect(int port) throws IOException, InterruptedException, AdbPairingRequiredException {
        synchronized (mLock) {
            if (isConnected()) {
                return false;
            }
            mAdbConnection = new AdbConnection.Builder(mHostAddress, port)
                    .setApi(mApi)
                    .setKeyPair(getAdbKeyPair())
                    .setDeviceName(Objects.requireNonNull(getDeviceName()))
                    .build();
            return mAdbConnection.connect(mTimeout, mTimeoutUnit, mThrowOnUnauthorised);
        }
    }

    /**
     * Attempt to connect to ADB via a host address and a port number.
     *
     * @param host Host address to use instead of taking it from the {@link #getHostAddress()}
     * @param port Port number
     * @return {@code true} if and only if the connection is successful. It returns {@code false} if the connection
     * attempt is unsuccessful, or it has already been made.
     * @throws IOException                      If the socket connection could not be made.
     * @throws InterruptedException             If timeout has reached.
     * @throws AdbAuthenticationFailedException If {@link #isThrowOnUnauthorised()} is set to {@code true}, and the
     *                                          ADB daemon has rejected the first authentication attempt, which
     *                                          indicates that the daemon has not saved the public key from a previous
     *                                          connection.
     * @throws AdbPairingRequiredException      If ADB lacks pairing
     */
    @WorkerThread
    public boolean connect(@NonNull String host, int port)
            throws IOException, InterruptedException, AdbPairingRequiredException {
        synchronized (mLock) {
            if (isConnected()) {
                return false;
            }
            mHostAddress = host;
            mAdbConnection = new AdbConnection.Builder(host, port)
                    .setApi(mApi)
                    .setKeyPair(getAdbKeyPair())
                    .setDeviceName(Objects.requireNonNull(getDeviceName()))
                    .build();
            return mAdbConnection.connect(mTimeout, mTimeoutUnit, mThrowOnUnauthorised);
        }
    }

    /**
     * Disconnect the underlying {@link AdbConnection}.
     *
     * @throws IOException If the underlying socket fails to close
     */
    public void disconnect() throws IOException {
        synchronized (mLock) {
            if (mAdbConnection != null) {
                mAdbConnection.close();
                mAdbConnection = null;
            }
        }
    }

    /**
     * Opens a {@link ShellStream} corresponding to the specified destination.
     * This routine will block until the connection completes.
     *
     * When a local transport is installed via {@link #setLocalShell(ShellProvider)} (Shizuku), the
     * request is handed to it and no ADB connection is touched at all.
     *
     * @param destination The destination to open on the target
     * @return {@link AdbStream} object corresponding to the specified destination
     * @throws IOException                  If the steam fails or no connection has been made
     * @throws InterruptedException         If the stream fails while sending the packet
     * @throws UnsupportedEncodingException If the destination cannot be encoded to UTF-8.
     */
    @WorkerThread
    @NonNull
    public ShellStream openStream(String destination) throws IOException, InterruptedException {
        ShellProvider local = mLocalShell;
        if (local != null) {
            return local.openShellStream(destination);
        }
        synchronized (mLock) {
            if (mAdbConnection != null && mAdbConnection.isConnected()) {
                try {
                    return new AdbStreamAdapter(mAdbConnection.open(destination));
                } catch (AdbPairingRequiredException e) {
                    throw new IllegalStateException(e);
                }
            }
            throw new IOException("Not connected to ADB.");
        }
    }

    /**
     * Pair with an ADB daemon given port number and pairing code.
     *
     * @param port        Port number
     * @param pairingCode The six-digit pairing code as string
     * @return {@code true} if the pairing is successful and {@code false} otherwise.
     * @throws Exception If pairing failed for some reason.
     */
    @WorkerThread
    @RequiresApi(Build.VERSION_CODES.GINGERBREAD)
    public boolean pair(int port, @NonNull String pairingCode) throws Exception {
        return pair(mHostAddress, port, pairingCode);
    }

    /**
     * Pair with an ADB daemon given host address, port number and pairing code.
     *
     * @param host        Host address to use instead of taking it from the {@link #getHostAddress()}
     * @param port        Port number
     * @param pairingCode The six-digit pairing code as string
     * @return {@code true} if the pairing is successful and {@code false} otherwise.
     * @throws Exception If pairing failed for some reason.
     */
    @WorkerThread
    @RequiresApi(Build.VERSION_CODES.GINGERBREAD)
    public boolean pair(@NonNull String host, int port, @NonNull String pairingCode) throws Exception {
        synchronized (mLock) {
            KeyPair keyPair = getAdbKeyPair();
            try (PairingConnectionCtx pairingClient = new PairingConnectionCtx(Objects.requireNonNull(host), port,
                    StringCompat.getBytes(Objects.requireNonNull(pairingCode), "UTF-8"), keyPair, getDeviceName())) {
                // TODO: 5/12/21 Return true/false instead of only exceptions
                pairingClient.start();
            }
            return true;
        }
    }

    /**
     * Close the underlying {@link AdbConnection} and destroy the private key.
     *
     * @throws IOException If socket fails to close.
     */
    @Override
    public void close() throws IOException {
        try {
            getPrivateKey().destroy();
        } catch (DestroyFailedException | NoSuchMethodError e) {
            e.printStackTrace();
        }
        if (mAdbConnection != null) {
            mAdbConnection.close();
            mAdbConnection = null;
        }
    }

    @NonNull
    private KeyPair getAdbKeyPair() {
        return new KeyPair(Objects.requireNonNull(getPrivateKey()), Objects.requireNonNull(getCertificate()));
    }
}
