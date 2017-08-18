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
import javax.net.ssl.SSLException;

import static io.netty.handler.ssl.SslUtils.toSSLHandshakeException;

final class Java9SslEngineWrapper extends JdkSslEngine {
    private final JdkApplicationProtocolNegotiator applicationNegotiator;

    Java9SslEngineWrapper(SSLEngine engine, JdkApplicationProtocolNegotiator applicationNegotiator) {
        super(engine);
        this.applicationNegotiator = applicationNegotiator;
        Java9SslUtils.configureAlpn(this, applicationNegotiator);
    }

    void selectProtocolIfClient() throws SSLException {
        if (getUseClientMode()) {
            try {
                applicationNegotiator.protocolListenerFactory().newListener(
                        this, applicationNegotiator.protocols())
                        .selected(Java9SslUtils.getApplicationProtocol(getWrappedEngine()));
            } catch (Throwable e) {
                throw toSSLHandshakeException(e);
            }
        }
    }
}
