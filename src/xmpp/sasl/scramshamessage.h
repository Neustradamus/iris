/*
 * Copyright (C) 2010  Tobias Markmann
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

#ifndef SCRAMSHAMESSAGE_H
#define SCRAMSHAMESSAGE_H

#include <QByteArray>
#include <QString>

#include "xmpp/base/randomnumbergenerator.h"

namespace XMPP {
    class SCRAMSHA1Message
    {
        public:
            SCRAMSHA1Message(const QString& authzid, const QString& authcid, const QByteArray& cnonce, const RandomNumberGenerator& rand);

            const QByteArray& getValue() {
                return value_;
            }

            bool isValid() const {
                return isValid_;
            }

        private:
            QByteArray value_;
            bool isValid_;
    };

    class SCRAMSHA224Message
    {
        public:
            SCRAMSHA224Message(const QString& authzid, const QString& authcid, const QByteArray& cnonce, const RandomNumberGenerator& rand);

            const QByteArray& getValue() {
                return value_;
            }

            bool isValid() const {
                return isValid_;
            }

        private:
            QByteArray value_;
            bool isValid_;
    };

    class SCRAMSHA256Message
    {
        public:
            SCRAMSHA256Message(const QString& authzid, const QString& authcid, const QByteArray& cnonce, const RandomNumberGenerator& rand);

            const QByteArray& getValue() {
                return value_;
            }

            bool isValid() const {
                return isValid_;
            }

        private:
            QByteArray value_;
            bool isValid_;
    };

    class SCRAMSHA384Message
    {
        public:
            SCRAMSHA384Message(const QString& authzid, const QString& authcid, const QByteArray& cnonce, const RandomNumberGenerator& rand);

            const QByteArray& getValue() {
                return value_;
            }

            bool isValid() const {
                return isValid_;
            }

        private:
            QByteArray value_;
            bool isValid_;
    };

    class SCRAMSHA512Message
    {
        public:
            SCRAMSHA512Message(const QString& authzid, const QString& authcid, const QByteArray& cnonce, const RandomNumberGenerator& rand);

            const QByteArray& getValue() {
                return value_;
            }

            bool isValid() const {
                return isValid_;
            }

        private:
            QByteArray value_;
            bool isValid_;
    };

}

#endif
