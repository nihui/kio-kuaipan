/*
 *  This file is part of kio_kuaipan, KIO slave for KingSoft KuaiPan
 *  Copyright (C) 2012 Ni Hui <shuizhuyuanluo@126.com>
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as
 *  published by the Free Software Foundation; either version 2 of
 *  the License or (at your option) version 3 or any later version
 *  accepted by the membership of KDE e.V. (or its successor approved
 *  by the membership of KDE e.V.), which shall act as a proxy
 *  defined in Section 14 of version 3 of the license.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef MULTIPARTDEVICE_H
#define MULTIPARTDEVICE_H

#include <QIODevice>

class MultiPartDevice : public QIODevice
{
public:
    explicit MultiPartDevice(QIODevice* dev, QObject* parent = 0);
    virtual ~MultiPartDevice();
    virtual bool atEnd() const;
    virtual qint64 bytesAvailable() const;
    virtual bool canReadLine() const;
    virtual void close();
    virtual bool isSequential() const;
    virtual bool open(OpenMode mode);
    virtual qint64 pos() const;
    virtual bool reset();
    virtual bool seek(qint64 pos);
    virtual qint64 size() const;
    void setBoundary(const QByteArray& b);
    void setContentDispositionHeader(const QByteArray& cd);
    void setContentTypeHeader(const QByteArray& ct);
protected:
    virtual qint64 readData(char* data, qint64 maxSize);
    virtual qint64 writeData(const char* data, qint64 maxSize);
private:
    QByteArray m_boundary;
    QByteArray m_contentDispositionHeader;
    QByteArray m_contentTypeHeader;
    QIODevice* m_contentDevice;
    qint64 m_pos;
};

#endif // MULTIPARTDEVICE_H
