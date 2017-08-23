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

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.function.BiFunction;


import static io.netty.handler.ssl.SslUtils.toSSLHandshakeException;

final class Java9SslEngine extends JdkSslEngine {
    private final JdkApplicationProtocolNegotiator applicationNegotiator;

    Java9SslEngine(SSLEngine engine, JdkApplicationProtocolNegotiator applicationNegotiator) {
        super(engine);
        this.applicationNegotiator = applicationNegotiator;
        Java9SslUtils.configureAlpn(this, applicationNegotiator);
    }

    private SSLEngineResult verifyProtocolSelection(SSLEngineResult result) throws SSLException {
        if (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED && getUseClientMode()) {
            String protocol = getApplicationProtocol();
            JdkApplicationProtocolNegotiator.ProtocolSelectionListener selectionListener =
                    applicationNegotiator.protocolListenerFactory().newListener(
                            this, applicationNegotiator.protocols());
            try {
                if (protocol == null || protocol.isEmpty()) {
                    selectionListener.unsupported();
                } else {
                    selectionListener.selected(protocol);
                }
            } catch (Throwable e) {
                throw toSSLHandshakeException(e);
            }
        }
        return result;
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer src, ByteBuffer dst) throws SSLException {
        return verifyProtocolSelection(super.wrap(src, dst));
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer[] srcs, ByteBuffer dst) throws SSLException {
        return verifyProtocolSelection(super.wrap(srcs, dst));
    }

    @Override
    public SSLEngineResult wrap(ByteBuffer[] srcs, int offset, int len, ByteBuffer dst) throws SSLException {
        return verifyProtocolSelection(super.wrap(srcs, offset, len, dst));
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer dst) throws SSLException {
        return verifyProtocolSelection(super.unwrap(src, dst));
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dsts) throws SSLException {
        return verifyProtocolSelection(super.unwrap(src, dsts));
    }

    @Override
    public SSLEngineResult unwrap(ByteBuffer src, ByteBuffer[] dst, int offset, int len) throws SSLException {
        return verifyProtocolSelection(super.unwrap(src, dst, offset, len));
    }

    @Override
    void setApplicationProtocol(String applicationProtocol) {
        // Do nothing as this is handled internally by the Java9 implementation of SSLEngine.
    }

    @Override
    public String getApplicationProtocol() {
        return Java9SslUtils.getApplicationProtocol(getWrappedEngine());
    }

    // These methods will override the methods defined by Java 9. As we compile with Java8 we can not add
    // @Override annotations here.
    public String getHandshakeApplicationProtocol() {
        return Java9SslUtils.getHandshakeApplicationProtocol(getWrappedEngine());
    }

    public void setHandshakeApplicationProtocolSelector(BiFunction<SSLEngine, List<String>, String> selector) {
        Java9SslUtils.setHandshakeApplicationProtocolSelector(getWrappedEngine(), selector);
    }

    public BiFunction<SSLEngine, List<String>, String> getHandshakeApplicationProtocolSelector() {
        return Java9SslUtils.getHandshakeApplicationProtocolSelector(getWrappedEngine());
    }
}
