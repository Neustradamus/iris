/*
 * jignle-s5b.h - Jingle SOCKS5 transport
 * Copyright (C) 2019  Sergey Ilinykh
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

#ifndef JINGLE_S5B_H
#define JINGLE_S5B_H

#include "jingle.h"

namespace XMPP {

class Client;

namespace Jingle {
namespace S5B {

extern const QString NS;

class Candidate {
public:
    enum Type {
        Assisted,
        Direct,
        Proxy,
        Tunnel
    };

    Candidate(const QDomElement &el);
    Candidate(const Candidate &other);
    ~Candidate();

private:
    class Private;
    QSharedDataPointer<Private> d;
};

class Manager;
class S5BTransport : public Transport
{
    Q_OBJECT
public:
    enum Mode {
        Tcp,
        Udp
    };

    inline S5BTransport() {}
    S5BTransport(const QDomElement &el);
    ~S5BTransport();

    void start();
    bool update(const QDomElement &el);
    QDomElement takeUpdate(QDomDocument *doc);
    bool isValid() const;
private:
    friend class Manager;
    static QSharedPointer<Transport> createOutgoing();

    class Private;
    QScopedPointer<Private> d;
};

class Manager : public TransportManager {
public:
    Manager(Client *client);

    QSharedPointer<Transport> sessionInitiate(); // outgoing. one have to call Transport::start to collect candidates
    QSharedPointer<Transport> sessionInitiate(const QDomElement &transportEl); // incoming
};

} // namespace S5B
} // namespace Jingle
} // namespace XMPP

#endif // JINGLE_S5B_H