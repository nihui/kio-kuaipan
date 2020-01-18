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

#ifndef KUAIPAN_H
#define KUAIPAN_H

#include <QObject>
#include <QFile>
#include <qjson/parser.h>
#include <QtOAuth/QtOAuth>
#include <kio/global.h>
#include <kio/slavebase.h>

class KuaiPanProtocol : public QObject, public KIO::SlaveBase
{
    Q_OBJECT
public:
    KuaiPanProtocol(const QByteArray& pool, const QByteArray& app);
    virtual ~KuaiPanProtocol();
    virtual void get(const KUrl& url);
//     virtual void put(const KUrl& url, int _mode, KIO::JobFlags _flags);
    virtual void copy(const KUrl& src, const KUrl& dest, int mode, KIO::JobFlags flags);
    virtual void rename(const KUrl& src, const KUrl& dest, KIO::JobFlags flags);
    virtual void stat(const KUrl& url);
    virtual void listDir(const KUrl& url);
    virtual void mkdir(const KUrl& url, int permissions);
    virtual void del(const KUrl& url, bool isfile);

private:
    bool authorize();

private Q_SLOTS:
    void slot_download_file_mimetype(KIO::Job*, const QString& type);
    void slot_download_file_data(KIO::Job*, const QByteArray& data);
    void slot_download_file_result(KJob*);
    void slot_upload_locate(KJob*);
    void slot_upload_file(KJob*);
    void slot_filecopy(KJob*);
    void slot_filemove(KJob*);
    void slot_metadata(KJob*);
    void slot_stat_metadata(KJob*);
    void slot_create_folder(KJob*);
    void slot_filedelete(KJob*);

private:
    QOAuth::Interface* m_qoauth;
    bool m_isAuthorized;
    QByteArray m_oauthToken;
    QByteArray m_oauthTokenSecret;

    QJson::Parser m_parser;

    QString m_upload_url;
    QFile m_localFile;
};

#endif // KUAIPAN_H
