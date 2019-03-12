/*
 * jignle-ft.h - Jingle file transfer
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

#include "jingle-ft.h"
#include "xmpp_client.h"
#include "xmpp_thumbs.h"
#include "xmpp_hash.h"

namespace XMPP {
namespace Jingle {

namespace FileTransfer {

const QString NS = QStringLiteral("urn:xmpp:jingle:apps:file-transfer:5");


QDomElement Range::toXml(QDomDocument *doc) const
{
    auto r = doc->createElement(QStringLiteral("range"));
    if (length) {
        r.setAttribute(QStringLiteral("length"), QString::number(length));
    }
    if (offset) {
        r.setAttribute(QStringLiteral("length"), QString::number(length));
    }
    auto h = hash.toXml(doc);
    if (!h.isNull()) {
        r.appendChild(h);
    }
    return r;
}

//----------------------------------------------------------------------------
// File
//----------------------------------------------------------------------------
class File::Private : public QSharedData
{
public:
    QDateTime date;
    QString   mediaType;
    QString   name;
    QString   desc;
    quint64   size = 0;
    Range     range;
    bool      rangeSupported = false;
    Hash      hash;
    Thumbnail thumbnail;
};

File::File()
{

}

File::~File()
{

}

File::File(const File &other) :
    d(other.d)
{

}

File::File(const QDomElement &file)
{
    QDateTime date;
    QString   mediaType;
    QString   name;
    QString   desc;
    size_t    size = 0;
    Range     range;
    Hash      hash;
    Thumbnail thumbnail;

    bool ok;

    for(QDomElement ce = file.firstChildElement();
        !ce.isNull(); ce = ce.nextSiblingElement()) {

        if (ce.tagName() == QLatin1String("date")) {
            date = QDateTime::fromString(ce.text().left(19), Qt::ISODate);
            if (!date.isValid()) {
                return;
            }

        } else if (ce.tagName() == QLatin1String("media-type")) {
            mediaType = ce.text();

        } else if (ce.tagName() == QLatin1String("name")) {
            name = ce.text();

        } else if (ce.tagName() == QLatin1String("size")) {
            size = ce.text().toULongLong(&ok);
            if (!ok) {
                return;
            }

        } else if (ce.tagName() == QLatin1String("range")) {
            if (ce.hasAttribute(QLatin1String("offset"))) {
                range.offset = ce.attribute(QLatin1String("offset")).toULongLong(&ok);
                if (!ok) {
                    return;
                }
            }
            if (ce.hasAttribute(QLatin1String("length"))) {
                range.offset = ce.attribute(QLatin1String("length")).toULongLong(&ok);
                if (!ok) {
                    return;
                }
            }
            QDomElement hashEl = ce.firstChildElement(QLatin1String("hash"));
            if (hashEl.namespaceURI() == QLatin1String("urn:xmpp:hashes:2")) {
                range.hash = Hash(hashEl);
                if (range.hash.type() == Hash::Type::Unknown) {
                    return;
                }
            }
            d->rangeSupported = true;

        } else if (ce.tagName() == QLatin1String("desc")) {
            desc = ce.text();

        } else if (ce.tagName() == QLatin1String("hash")) {
            if (ce.namespaceURI() == QLatin1String(XMPP_HASH_NS)) {
                hash = Hash(ce);
                if (hash.type() == Hash::Type::Unknown) {
                    return;
                }
            }

        } else if (ce.tagName() == QLatin1String("hash-used")) {
            if (ce.namespaceURI() == QLatin1String(XMPP_HASH_NS)) {
                hash = Hash(ce);
                if (hash.type() == Hash::Type::Unknown) {
                    return;
                }
            }

        } else if (ce.tagName() == QLatin1String("thumbnail")) {
            thumbnail = Thumbnail(ce);
        }
    }

    auto p = new Private;
    p->date = date;
    p->mediaType = mediaType;
    p->name = name;
    p->desc = desc;
    p->size = size;
    p->range = range;
    p->hash = hash;
    p->thumbnail = thumbnail;

    d = p;
}

QDomElement File::toXml(QDomDocument *doc) const
{
    if (!isValid()) {
        return QDomElement();
    }
    QDomElement el = doc->createElement(QStringLiteral("file"));
    if (d->date.isValid()) {
        el.appendChild(doc->createElement(QStringLiteral("date"))).setNodeValue(d->date.toString(Qt::ISODate));
    }
    if (d->desc.size()) {
        el.appendChild(doc->createElement(QStringLiteral("desc"))).setNodeValue(d->desc);
    }
    if (d->hash.isValid()) {
        el.appendChild(d->hash.toXml(doc));
    }
    if (d->mediaType.size()) {
        el.appendChild(doc->createElement(QStringLiteral("media-type"))).setNodeValue(d->mediaType);
    }
    if (d->name.size()) {
        el.appendChild(doc->createElement(QStringLiteral("name"))).setNodeValue(d->name);
    }
    if (d->size) {
        el.appendChild(doc->createElement(QStringLiteral("size"))).setNodeValue(QString::number(d->size));
    }
    if (d->rangeSupported || d->range.isValid()) {
        el.appendChild(d->range.toXml(doc));
    }
    if (d->thumbnail.isValid()) {
        el.appendChild(d->thumbnail.toXml(doc));
    }
    return el;
}

QDateTime File::date() const
{
    return d? d->date : QDateTime();
}

QString File::description() const
{
    return d? d->desc : QString();
}

Hash File::hash() const
{
    return d? d->hash : Hash();
}

QString File::mediaType() const
{
    return d? d->mediaType : QString();
}

QString File::name() const
{
    return d? d->name : QString();
}

quint64 File::size() const
{
    return d? d->size : 0;
}

Range File::range() const
{
    return d? d->range : Range();
}

Thumbnail File::thumbnail() const
{
    return d? d->thumbnail: Thumbnail();
}

void File::setDate(const QDateTime &date)
{
    ensureD()->date = date;
}

void File::setDescription(const QString &desc)
{
    ensureD()->desc = desc;
}

void File::setHash(const Hash &hash)
{
    ensureD()->hash = hash;
}

void File::setMediaType(const QString &mediaType)
{
    ensureD()->mediaType = mediaType;
}

void File::setName(const QString &name)
{
    ensureD()->name = name;
}

void File::setSize(quint64 size)
{
    ensureD()->size = size;
}

void File::setRange(const Range &range)
{
    ensureD()->range = range;
    d->rangeSupported = true;
}

void File::setThumbnail(const Thumbnail &thumb)
{
    ensureD()->thumbnail = thumb;
}

File::Private *File::ensureD()
{
    if (!d) {
        d = new Private;
    }
    return d.data();
}

//----------------------------------------------------------------------------
// Checksum
//----------------------------------------------------------------------------
Checksum::Checksum(const QDomElement &cs) :
    ContentBase(cs)
{
    file = File(cs.firstChildElement(QLatin1String("file")));
}

bool Checksum::isValid() const
{
    return ContentBase::isValid() && file.isValid();
}

QDomElement Checksum::toXml(QDomDocument *doc) const
{
    auto el = ContentBase::toXml(doc, "checksum");
    if (!el.isNull()) {
        el.appendChild(file.toXml(doc));
    }
    return el;
}

//----------------------------------------------------------------------------
// Received
//----------------------------------------------------------------------------
QDomElement Received::toXml(QDomDocument *doc) const
{
    return ContentBase::toXml(doc, "received");
}

//----------------------------------------------------------------------------
// ApplicationManager
//----------------------------------------------------------------------------
Manager::Manager(QObject *parent):
    XMPP::Jingle::ApplicationManager(parent)
{

}

void Manager::setJingleManager(XMPP::Jingle::Manager *jm)
{
    jingleManager = jm;
}

Application* Manager::startApplication(const ApplicationManagerPad::Ptr &pad, const QString &contentName, Origin creator, Origin senders)
{
    auto app = new Application(pad.staticCast<Pad>(), contentName, creator, senders); // ContentOrigin::Remote
    if (app->isValid()) {
        return app;
    }
    delete app;
    return nullptr;
}

ApplicationManagerPad* Manager::pad(Session *session)
{
    return new Pad(this, session);
}

void Manager::closeAll()
{

}

Client *Manager::client()
{
    if (jingleManager) {
        return jingleManager->client();
    }
    return nullptr;
}

//----------------------------------------------------------------------------
// ApplicationManager
//----------------------------------------------------------------------------
class Application::Private
{
public:
    enum State {
        Created,          // just after constructor
        SettingTransport, // either side sets transport to app either with initial offer of later update
        Pending,          // waits for session-accept or content-accept
        Connecting,       // s5b/ice probes etc
        Active            // active transfer. transport is connected
    };

    State   state;
    QSharedPointer<Pad> pad;
    QString contentName;
    File    file;
    Origin  creator;
    Origin  senders;
    QSharedPointer<Transport> transport;
};

Application::Application(const QSharedPointer<Pad> &pad, const QString &contentName, Origin creator, Origin senders) :
    d(new Private)
{
    d->pad     = pad;
    d->contentName = contentName;
    d->creator = creator;
    d->senders = senders;
}

Application::~Application()
{

}

QString Application::contentName() const
{
    return d->contentName;
}

Application::SetDescError Application::setDescription(const QDomElement &description)
{
    d->file = File(description.firstChildElement("file"));
    return d->file.isValid()? Ok: Unparsed;
}

bool Application::setTransport(const QSharedPointer<Transport> &transport)
{
    if (transport->features() & Transport::Reliable) {
        d->transport = transport;
        d->state = Private::Pending;
        return true;
    }
    return false;
}

QSharedPointer<Transport> Application::transport() const
{
    // TODO
    return QSharedPointer<Transport>();
}

Jingle::Action Application::outgoingUpdateType() const
{
    switch (d->state) {
    case Private::Created:
        break;
    case Private::Connecting:
    case Private::Active:
        return d->transport->outgoingUpdateType();
    case Private::Pending:
    default:
        break;
    }
    return Jingle::NoAction; // TODO
}

bool Application::isReadyForSessionAccept() const
{
    return false; // TODO
}

QDomElement Application::takeOutgoingUpdate()
{
    if (d->state == Private::Connecting || d->state == Private::Active) {
        return d->transport->takeOutgoingUpdate();
    }
    if (d->state == Private::Created && d->file.isValid()) { // basically when we come to this function Created is possible only for outgoing content
        if (d->file.thumbnail().data.size()) {
            auto thumb = d->file.thumbnail();
            auto bm = d->pad->manager()->client()->bobManager();
            BoBData data = bm->append(thumb.data, thumb.mimeType);
            thumb.uri = QLatin1String("cid:") + data.cid();
            d->file.setThumbnail(thumb);
        }
        auto doc = d->pad->manager()->client()->doc();
        ContentBase cb(d->pad->session()->role(), d->contentName);
        cb.senders = d->senders;
        auto cel = cb.toXml(doc, "content");
        cel.appendChild(doc->createElementNS(NS, "description")).appendChild(d->file.toXml(doc));
        return cel;
    }
    return QDomElement(); // TODO
}

QDomElement Application::sessionAcceptContent() const
{
    return QDomElement(); // TODO
}

bool Application::wantBetterTransport(const QSharedPointer<Transport> &t) const
{
    Q_UNUSED(t)
    return true; // TODO check
}

bool Application::isValid() const
{
    return d->file.isValid();
}

Pad::Pad(Manager *manager, Session *session) :
    _manager(manager),
    _session(session)
{

}

QDomElement Pad::takeOutgoingSessionInfoUpdate()
{
    return QDomElement(); // TODO
}

QString Pad::ns() const
{
    return NS;
}

Session *Pad::session() const
{
    return _session;
}



} // namespace FileTransfer
} // namespace Jingle
} // namespace XMPP
