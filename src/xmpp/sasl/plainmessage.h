/*
 * Copyright (C) 2008  Remko Troncon
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
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

#ifndef PLAINMESSAGE_H
#define PLAINMESSAGE_H

#include <QByteArray>
#include <QString>

namespace XMPP {
    class PLAINMessage
    {
        public:
            PLAINMessage(const QString& authzid, const QString& authcid, const QByteArray& password);

            const QByteArray& getValue() {
                return value_;
            }

        private:
            QByteArray value_;
    };
}

#endif
