/*
 * Copyright 2017 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.netty.handler.ssl;

import static io.netty.util.internal.ObjectUtil.checkNotNull;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.PrivilegedExceptionAction;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import io.netty.util.internal.EmptyArrays;
import io.netty.util.internal.PlatformDependent;
import io.netty.util.internal.StringUtil;
import io.netty.util.internal.logging.InternalLogger;
import io.netty.util.internal.logging.InternalLoggerFactory;

final class Java9SslUtils {
    private static final InternalLogger log = InternalLoggerFactory.getInstance(Java9SslUtils.class);
    private static final Method SET_APPLICATION_PROTOCOL;
    private static final Method GET_APPLICATION_PROTOCOL;
    private static final Method SET_HANDSHAKE_APPLICATION_PROTOCOL_SELECTOR;
    private static final Class<?> BI_FUNCTION_CLASS;

    static {
        Method setter = null;
        Method getter = null;
        Method selector = null;
        Class<?> biFunction = null;

        int version = PlatformDependent.javaVersion();
        if (version >= 9) {
            try {
                SSLContext context = SSLContext.getInstance(JdkSslContext.PROTOCOL);
                context.init(null, null, null);
                SSLEngine engine = context.createSSLEngine();

                getter = AccessController.doPrivileged(new PrivilegedExceptionAction<Method>() {
                    @Override
                    public Method run() throws Exception {
                        return SSLEngine.class.getMethod("getApplicationProtocol");
                    }
                });
                getter.invoke(engine);

                setter = AccessController.doPrivileged(new PrivilegedExceptionAction<Method>() {
                    @Override
                    public Method run() throws Exception {
                        return SSLParameters.class.getMethod("setApplicationProtocols", String[].class);
                    }
                });
                setter.invoke(engine.getSSLParameters(), new Object[] { EmptyArrays.EMPTY_STRINGS });

                biFunction = Class.forName(
                        "java.util.function.BiFunction", false, Java9SslUtils.class.getClassLoader());
                final Class<?> biFunctionClass = biFunction;
                selector = AccessController.doPrivileged(new PrivilegedExceptionAction<Method>() {
                    @Override
                    public Method run() throws Exception {
                        return SSLEngine.class.getMethod("setHandshakeApplicationProtocolSelector", biFunctionClass);
                    }
                });
            } catch (Throwable t) {
                log.error("Unable to initialize Java9SslUtils, but the detected javaVersion was: {}", version, t);
                getter = null;
                setter = null;
                biFunction = null;
                selector = null;
            }
        }

        GET_APPLICATION_PROTOCOL = getter;
        SET_APPLICATION_PROTOCOL = setter;
        BI_FUNCTION_CLASS = biFunction;
        SET_HANDSHAKE_APPLICATION_PROTOCOL_SELECTOR = selector;
    }

    private Java9SslUtils() {
    }

    static boolean supportsAlpn() {
        return GET_APPLICATION_PROTOCOL != null;
    }

    static void configureAlpn(JdkSslEngine engine, JdkApplicationProtocolNegotiator applicationNegotiator) {
        List<String> supportedProtocols = applicationNegotiator.protocols();

        SSLEngine wrapped = engine.getWrappedEngine();
        SSLParameters params = wrapped.getSSLParameters();
        setApplicationProtocols(params, supportedProtocols);
        wrapped.setSSLParameters(params);

        if (!wrapped.getUseClientMode()) {
            installSelector(engine, applicationNegotiator);
        }
    }

    static String getApplicationProtocol(SSLEngine sslEngine) {
        try {
            return (String) GET_APPLICATION_PROTOCOL.invoke(sslEngine);
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static void setApplicationProtocols(SSLParameters parameters, List<String> supportedProtocols) {
        String[] protocolArray = supportedProtocols.toArray(EmptyArrays.EMPTY_STRINGS);
        try {
            SET_APPLICATION_PROTOCOL.invoke(parameters, new Object[]{ protocolArray });
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static void installSelector(final JdkSslEngine sslEngine,
                                        final JdkApplicationProtocolNegotiator applicationProtocolNegotiator) {
        checkNotNull(applicationProtocolNegotiator, "applicationProtocolNegotiator");

        Object biFunction = AccessController.doPrivileged(new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                return Proxy.newProxyInstance(Java9SslUtils.class.getClassLoader(), new Class[]{ BI_FUNCTION_CLASS },
                        new AlpnSelector(sslEngine, applicationProtocolNegotiator));
            }
        });

        try {
            SET_HANDSHAKE_APPLICATION_PROTOCOL_SELECTOR.invoke(sslEngine.getWrappedEngine(), biFunction);
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static final class AlpnSelector implements InvocationHandler {
        private final SSLEngine jdkSslEngine;
        private final JdkApplicationProtocolNegotiator applicationNegotiator;
        private final Set<String> protocols;

        AlpnSelector(JdkSslEngine jdkSslEngine, JdkApplicationProtocolNegotiator applicationNegotiator) {
            this.jdkSslEngine = jdkSslEngine;
            this.applicationNegotiator = applicationNegotiator;
            protocols = Collections.unmodifiableSet(new LinkedHashSet<String>(applicationNegotiator.protocols()));
        }

        @SuppressWarnings("unchecked")
        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            // Assert that it is actually called via the BiConsumer that we expect.
            assert "apply".equals(method.getName()) : "unexpected method " + method.getName();
            assert args.length == 2 : "unexpected lengths of arguments " +  args.length;
            assert args[0] instanceof SSLEngine;

            JdkApplicationProtocolNegotiator.ProtocolSelector selector = applicationNegotiator.protocolSelectorFactory()
                    .newSelector(jdkSslEngine, protocols);

            try {
                String selected = selector.select((List<String>) args[1]);
                return selected == null ? StringUtil.EMPTY_STRING : selected;
            } catch (Exception cause) {
                // Returning null means we want to fail the handshake.
                //
                // See http://download.java.net/java/jdk9/docs/api/javax/net/ssl/
                // SSLEngine.html#setHandshakeApplicationProtocolSelector-java.util.function.BiFunction-
                return null;
            }
        }
    }
}
