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

#include <QObject>
#include <QtTest/QtTest>
#include <QtCrypto>

#include "qttestutil/qttestutil.h"
#include "xmpp/sasl/scramsharesponse.h"
#include "xmpp/sasl/scramshasignature.h"
#include "xmpp/base/unittest/incrementingrandomnumbergenerator.h"

using namespace XMPP;

class SCRAMSHA1ResponseTest : public QObject
{
        Q_OBJECT

    private slots:
        void testConstructor_WithAuthzid() {

        }

        void testConstructor_WithoutAuthzid() {
            if (QCA::isSupported("hmac(sha1)")) {
                SCRAMSHA1Response resp1("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096",
                                    "pencil", "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL", "", IncrementingRandomNumberGenerator(255));
                const QCA::SecureArray sig = resp1.getServerSignature();
                QByteArray resp_sig("v=rmF9pqV8S7suAoZWja4dJRkFsKQ=");
                SCRAMSHA1Signature sig1(resp_sig, sig);
                QByteArray resp1_ok("c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=");
                QCOMPARE(resp1.getValue(), resp1_ok);
                QVERIFY(sig1.isValid());
            } else {
                QFAIL("hmac(sha1) not supported in QCA.");
            }
        }

    private:
        QCA::Initializer initializer;
};

class SCRAMSHA224ResponseTest : public QObject
{
        Q_OBJECT

    private slots:
        void testConstructor_WithAuthzid() {

        }

        void testConstructor_WithoutAuthzid() {
            if (QCA::isSupported("hmac(sha224)")) {
                SCRAMSHA224Response resp1("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096",
                                    "pencil", "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL", "", IncrementingRandomNumberGenerator(255));
                const QCA::SecureArray sig = resp1.getServerSignature();
                QByteArray resp_sig("v=rmF9pqV8S7suAoZWja4dJRkFsKQ=");
                SCRAMSHA224Signature sig1(resp_sig, sig);
                QByteArray resp1_ok("c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=");
                QCOMPARE(resp1.getValue(), resp1_ok);
                QVERIFY(sig1.isValid());
            } else {
                QFAIL("hmac(sha224) not supported in QCA.");
            }
        }

    private:
        QCA::Initializer initializer;
};

class SCRAMSHA256ResponseTest : public QObject
{
        Q_OBJECT

    private slots:
        void testConstructor_WithAuthzid() {

        }

        void testConstructor_WithoutAuthzid() {
            if (QCA::isSupported("hmac(sha256)")) {
                SCRAMSHA256Response resp1("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096",
                                    "pencil", "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL", "", IncrementingRandomNumberGenerator(255));
                const QCA::SecureArray sig = resp1.getServerSignature();
                QByteArray resp_sig("v=rmF9pqV8S7suAoZWja4dJRkFsKQ=");
                SCRAMSHA256Signature sig1(resp_sig, sig);
                QByteArray resp1_ok("c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=");
                QCOMPARE(resp1.getValue(), resp1_ok);
                QVERIFY(sig1.isValid());
            } else {
                QFAIL("hmac(sha256) not supported in QCA.");
            }
        }

    private:
        QCA::Initializer initializer;
};

class SCRAMSHA384ResponseTest : public QObject
{
        Q_OBJECT

    private slots:
        void testConstructor_WithAuthzid() {

        }

        void testConstructor_WithoutAuthzid() {
            if (QCA::isSupported("hmac(sha384)")) {
                SCRAMSHA384Response resp1("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096",
                                    "pencil", "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL", "", IncrementingRandomNumberGenerator(255));
                const QCA::SecureArray sig = resp1.getServerSignature();
                QByteArray resp_sig("v=rmF9pqV8S7suAoZWja4dJRkFsKQ=");
                SCRAMSHA384Signature sig1(resp_sig, sig);
                QByteArray resp1_ok("c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=");
                QCOMPARE(resp1.getValue(), resp1_ok);
                QVERIFY(sig1.isValid());
            } else {
                QFAIL("hmac(sha384) not supported in QCA.");
            }
        }

    private:
        QCA::Initializer initializer;
};

class SCRAMSHA512ResponseTest : public QObject
{
        Q_OBJECT

    private slots:
        void testConstructor_WithAuthzid() {

        }

        void testConstructor_WithoutAuthzid() {
            if (QCA::isSupported("hmac(sha512)")) {
                SCRAMSHA512Response resp1("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096",
                                    "pencil", "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL", "", IncrementingRandomNumberGenerator(255));
                const QCA::SecureArray sig = resp1.getServerSignature();
                QByteArray resp_sig("v=rmF9pqV8S7suAoZWja4dJRkFsKQ=");
                SCRAMSHA512Signature sig1(resp_sig, sig);
                QByteArray resp1_ok("c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=");
                QCOMPARE(resp1.getValue(), resp1_ok);
                QVERIFY(sig1.isValid());
            } else {
                QFAIL("hmac(sha512) not supported in QCA.");
            }
        }

    private:
        QCA::Initializer initializer;
};

QTTESTUTIL_REGISTER_TEST(SCRAMSHA1ResponseTest);
QTTESTUTIL_REGISTER_TEST(SCRAMSHA224ResponseTest);
QTTESTUTIL_REGISTER_TEST(SCRAMSHA256ResponseTest);
QTTESTUTIL_REGISTER_TEST(SCRAMSHA384ResponseTest);
QTTESTUTIL_REGISTER_TEST(SCRAMSHA512ResponseTest);
#include "scramsharesponsetest.moc"
